#!/usr/bin/env bash
# E5.1 live MySQL gate for the already-ported R9 read-only/catalog/plugin
# surface. The gate deliberately runs the production statekit binary and the
# official image's native mysql client; it does not use the Go fake Runner.
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
readonly CLIENT_TIMEOUT_SECONDS=45
readonly CLIENT_CREATE_TIMEOUT_SECONDS=30
readonly CLIENT_START_TIMEOUT_SECONDS=30
readonly NATIVE_CONNECT_TIMEOUT_SECONDS=3
readonly CLEANUP_TIMEOUT_SECONDS=20
readonly PREFLIGHT_TIMEOUT_SECONDS=30
readonly MYSQL_SERVICE_USER='999:999'
readonly CLIENT_USER='65532:65532'
readonly SERVER_ROOT_SECRET_TARGET='/run/secrets/mysql-root-password'
readonly SERVER_USER_SECRET_TARGET='/run/secrets/mysql-user-password'
readonly CLIENT_SECRET_TARGET='/run/secrets/mysql-client.cnf'
readonly NATIVE_AUTH_FAILURE_MARKER='ERROR 1045 (28000): Access denied for user'
readonly NATIVE_CONNECTION_FAILURE_MARKER="ERROR 2003 (HY000): Can't connect to MySQL server"
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
NETWORK=''
DB_CONTAINER=''
DB_CONTAINER_ID=''
DB_HOST=''
DB_RESERVED=0
NETWORK_RESERVED=0
CLIENT_IMAGE_RESERVED=0
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
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_PASSWORD=''
LIVE_PASSWORD=''
BAD_PASSWORD=''
CLIENT_IMAGE=''
SERVER_ROOT_SECRET=''
SERVER_USER_SECRET=''
CLIENT_SECRET=''
BAD_CLIENT_SECRET=''
declare -a CASE_RESULTS=()
declare -a OWNED_CLIENT_NAMES=()
declare -a OWNED_CLIENT_IDS=()
declare -a OWNED_SECRET_NAMES=()

set_note() {
  if [[ "$SETUP_NOTE" == 'none' ]]; then
    SETUP_NOTE="$1"
  fi
}

record_case() {
  local case_id="$1"
  local result="$2"
  CASE_RESULTS+=("$case_id=$result")
  case "$result" in
    pass) PASSED=$((PASSED + 1)) ;;
    fail) FAILED=$((FAILED + 1)) ;;
    skipped) SKIPPED=$((SKIPPED + 1)) ;;
    *) FAILED=$((FAILED + 1)) ;;
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

mark_remaining_skipped() {
  local case_id
  for case_id in "${CASE_IDS[@]:1}"; do
    record_case "$case_id" skipped
  done
}

write_report() {
  if (( REPORT_WRITTEN == 1 )); then
    return 0
  fi
  if (( REPORT_PREPARED != 1 )); then
    return 1
  fi
  local report_tmp
  if ! report_tmp=$(mktemp "$REPORT_DIR/.report.tmp.XXXXXX"); then
    return 1
  fi
  if ! {
    printf '%s\n' 'schema: e5.1-mysql-live-v1'
    printf 'image: %s\n' "$MYSQL_IMAGE"
    printf 'cases_total: %d\n' "${#CASE_IDS[@]}"
    printf 'cases_passed: %d\n' "$PASSED"
    printf 'cases_failed: %d\n' "$FAILED"
    printf 'cases_skipped: %d\n' "$SKIPPED"
    if (( EXECUTION_COMPLETE == 1 && EXECUTION_RC == 0 && FINAL_RC == 0 && CANCELLED == 0 && ${#CASE_RESULTS[@]} == ${#CASE_IDS[@]} && PASSED == ${#CASE_IDS[@]} && FAILED == 0 && SKIPPED == 0 && CLEANUP_FAILED == 0 )); then
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
    printf '%s\n' 'scope: mysql.version, mysql.db_list, mysql.db_exists, mysql.plugins_list, mysql.plugin_status'
    printf '%s\n' 'independent_checks: native mysql client database and plugin postconditions'
    printf '%s\n' 'limitations: no full R9 live coverage, no mutation coverage, no broker/PostgreSQL/SQLite coverage, no live Salt differential parity; SIGKILL or runner loss can prevent cleanup/reporting'
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

container_exists_state() {
  local ref="$1" rc=0
  if timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" container exists "$ref" >/dev/null 2>/dev/null; then
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
  if timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" network exists "$ref" >/dev/null 2>/dev/null; then
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
  if timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" image exists "$ref" >/dev/null 2>/dev/null; then
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

  timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" stop --time 5 "$ref" >/dev/null 2>/dev/null || stop_rc=$?
  if (( stop_rc != 0 )); then
    timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" kill "$ref" >/dev/null 2>/dev/null || kill_rc=$?
  fi
  timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" rm --force --volumes "$ref" >/dev/null 2>/dev/null || rm_rc=$?
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
  [[ -n "$RUNTIME" && -n "$NETWORK" && "$NETWORK_RESERVED" == 1 ]] || return 0
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
  timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" network rm "$NETWORK" >/dev/null 2>/dev/null || rm_rc=$?
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
  [[ -n "$RUNTIME" && -n "$CLIENT_IMAGE" && "$CLIENT_IMAGE_RESERVED" == 1 ]] || return 0
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
  timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" rmi --force "$CLIENT_IMAGE" >/dev/null 2>/dev/null || rm_rc=$?
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
  if timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" secret exists "$ref" >/dev/null 2>/dev/null; then
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
  timeout "$CLEANUP_TIMEOUT_SECONDS" "$RUNTIME" secret rm "$name" >/dev/null 2>/dev/null || rm_rc=$?
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
    rm -rf -- "$WORK_DIR" || true
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
  while (( index < ${#OWNED_CLIENT_NAMES[@]} )); do
    cleanup_container "${OWNED_CLIENT_NAMES[index]}" "${OWNED_CLIENT_IDS[index]}" || true
    index=$((index + 1))
  done
  if (( DB_RESERVED == 1 )); then
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
    printf '%s\n' 'e5.1: report write failed' >&2
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
      "$secret_lines" == "$BAD_CLIENT_SECRET|65532|65532|400" ]]
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
  SERVER_ROOT_SECRET="statekit-e51-root-$$"
  SERVER_USER_SECRET="statekit-e51-user-$$"
  CLIENT_SECRET="statekit-e51-client-$$"
  BAD_CLIENT_SECRET="statekit-e51-bad-client-$$"
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
  NETWORK="statekit-e51-net-$$"
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
  if ! timeout 30 "$RUNTIME" network create --internal "$NETWORK" >"$WORK_DIR/network.out" 2>"$WORK_DIR/network.err"; then
    set_note 'private-network-create-failed'
    return 1
  fi
  verify_private_network_policy
}

start_mysql() {
  local id_path="$WORK_DIR/server.id" container_id
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
  CLIENT_IMAGE="statekit-e51-client:$$"
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

run_client_container() {
  local stdout_path="$1" stderr_path="$2"
  shift 2
  local name="statekit-e51-client-$$-$CLIENT_SEQUENCE" id_path wait_path start_rc=0 wait_rc=0
  local log_rc=0 container_id='' wait_value='' index
  CLIENT_SEQUENCE=$((CLIENT_SEQUENCE + 1))
  LAST_CLIENT_CLASS='setup'
  LAST_CLIENT_EXIT_RC=125
  : >"$stdout_path"
  : >"$stderr_path"
  if ! reserve_container_name "$name"; then
    return 125
  fi
  index=${#OWNED_CLIENT_NAMES[@]}
  OWNED_CLIENT_NAMES+=("$name")
  OWNED_CLIENT_IDS+=('')
  id_path="$WORK_DIR/client-${CLIENT_SEQUENCE}.id"
  wait_path="$WORK_DIR/client-${CLIENT_SEQUENCE}.wait"
  timeout "$CLIENT_CREATE_TIMEOUT_SECONDS" "$RUNTIME" create --name "$name" "$@" >"$id_path" 2>"$WORK_DIR/client-${CLIENT_SEQUENCE}.create.err" || start_rc=$?
  if (( start_rc != 0 )); then
    LAST_CLIENT_CLASS='setup'
    if ! cleanup_container "$name" ''; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  container_id=$(tr -d '[:space:]' <"$id_path")
  if [[ ! "$container_id" =~ ^[[:alnum:]_.-]+$ ]]; then
    LAST_CLIENT_CLASS='setup'
    if ! cleanup_container "$name" ''; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  OWNED_CLIENT_IDS[index]="$container_id"
  if ! verify_created_container_policy "$container_id" client; then
    LAST_CLIENT_CLASS='setup'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
  timeout "$CLIENT_START_TIMEOUT_SECONDS" "$RUNTIME" start "$container_id" >"$WORK_DIR/client-${CLIENT_SEQUENCE}.start.out" 2>"$WORK_DIR/client-${CLIENT_SEQUENCE}.start.err" || start_rc=$?
  if (( start_rc != 0 )); then
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
  LAST_CLIENT_EXIT_RC="$wait_value"
  timeout "$CLIENT_CREATE_TIMEOUT_SECONDS" "$RUNTIME" logs "$container_id" >"$stdout_path" 2>"$stderr_path" || log_rc=$?
  if (( log_rc != 0 )); then
    LAST_CLIENT_CLASS='runtime'
    if ! cleanup_container "$name" "$container_id"; then
      LAST_CLIENT_CLASS='cleanup'
    fi
    return 125
  fi
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
  local secret_name="$1" host="$2" port="$3" sql="$4" stdout_path="$5" stderr_path="$6"
  run_client_container "$stdout_path" "$stderr_path" \
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
    --user="$TEST_USER" \
    --database="$SEED_DB" \
    --batch \
    --skip-column-names \
    --execute="$sql"
}

# The single-quoted value is intentionally expanded by /bin/sh in the client.
# shellcheck disable=SC2016
readonly STATEKIT_SCRIPT='set -eu
secret_source="$1"
function_name="$2"
extra_json="$3"
host="$4"
port="$5"
database="$6"
credentials_file=/tmp/mysql-client.cnf
cp -- "$secret_source" "$credentials_file"
chmod 600 "$credentials_file"
trap '\''rm -f -- "$credentials_file"'\'' EXIT
connection_user=$(awk -F= '\''$1 == "user" { print substr($0, index($0, "=") + 1); exit }'\'' "$credentials_file")
connection_pass=$(awk -F= '\''$1 == "password" { print substr($0, index($0, "=") + 1); exit }'\'' "$credentials_file")
test -n "$connection_user" -a -n "$connection_pass"
payload=$(printf '\''{"connection_user":"%s","connection_host":"%s","connection_port":"%s","connection_db":"%s","connection_pass":"%s"%s}'\'' "$connection_user" "$host" "$port" "$database" "$connection_pass" "$extra_json")
printf '\''%s'\'' "$payload" | /usr/local/bin/statekit exec "$function_name" --stdin --output json'

statekit_call() {
  local secret_name="$1" function_name="$2" extra_json="$3" host="$4" port="$5" stdout_path="$6" stderr_path="$7"
  run_client_container "$stdout_path" "$stderr_path" \
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
    -- "$CLIENT_SECRET_TARGET" "$function_name" "$extra_json" "$host" "$port" "$SEED_DB"
}

value_free_files() {
  local path content
  for path in "$@"; do
    [[ -f "$path" ]] || continue
    content=$(<"$path")
    if [[ "$content" == *"$ROOT_PASSWORD"* || "$content" == *"$LIVE_PASSWORD"* || "$content" == *"$BAD_PASSWORD"* ]]; then
      return 1
    fi
  done
}

native_failure_classification() {
  local kind="$1" execution_class="$2" rc="$3" stdout_path="$4" stderr_path="$5" marker=''
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
    printf '%s\n' 'unexpected-success'
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
  if { grep -F -q -- "$marker" "$stdout_path" 2>/dev/null || grep -F -q -- "$marker" "$stderr_path" 2>/dev/null; }; then
    printf '%s\n' 'expected'
  else
    printf '%s\n' 'unexpected-error'
  fi
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
    mark_remaining_skipped
    return 1
  fi
  if ! command -v timeout >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
    set_note 'required-local-tool-missing'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi
  if ! select_runtime || ! runtime_preflight; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi
  if ! WORK_DIR=$(mktemp -d); then
    set_note 'temporary-work-directory-create-failed'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi
  DB_CONTAINER="statekit-e51-mysql-$$"
  DB_HOST="$DB_CONTAINER"
  if ! pull_and_verify_image || ! build_client_image || ! create_private_network ||
    ! generate_credentials || ! create_runtime_secrets; then
    set_note 'runtime-or-resource-setup-failed'
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi
  if ! reserve_container_name "$DB_CONTAINER"; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi
  DB_RESERVED=1
  if ! start_mysql; then
    record_case "${CASE_IDS[0]}" fail
    mark_remaining_skipped
    return 1
  fi

  run_case 'mysql-readiness-authenticated-select-1' check_readiness
  if (( PASSED != 1 )); then
    mark_remaining_skipped
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

  EXECUTION_COMPLETE=1
  if (( ${#CASE_RESULTS[@]} != ${#CASE_IDS[@]} || PASSED != ${#CASE_IDS[@]} || FAILED != 0 || SKIPPED != 0 )); then
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
