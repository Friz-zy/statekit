#!/usr/bin/env bash
# GitHub-only orchestration for the runner-bundled PostgreSQL live gate.
set -euo pipefail
set +x

# This must remain the first live-controller operation: no report reset, user,
# DB, firewall, cluster, or build mutation precedes runner/event/toolchain
# preflight. The local workspace/container self-test paths below create and
# remove only their own /dev/shm directories with mocked Podman calls and
# never reach the live controller.
self_test_mode=''
dig_contract_only=0
case "${1:-}" in
  --dig-contract-only)
    [[ "$#" == 1 ]] || exit 1
    dig_contract_only=1
    python3 -I tests/live/dig/orchestration.py --runner-preflight
    ;;
  --preflight-only)
    [[ "$#" == 1 ]] || exit 1
    python3 tests/live/postgres/run.py --preflight-only
    exit 0
    ;;
  --workspace-self-test) self_test_mode=workspace ;;
  --container-lifecycle-self-test) self_test_mode=container-lifecycle ;;
  *)
    python3 tests/live/postgres/run.py --preflight-only
    ;;
esac

readonly ROOT="${GITHUB_WORKSPACE:-$PWD}"
readonly REPORT_DIR="$ROOT/artifacts/postgres-live"
readonly REPORT_PATH="$REPORT_DIR/report.txt"
readonly RUNNER_UID="$(id -u)"
readonly RUNNER_GID="$(id -g)"
readonly EXEC_TMPFS_OPTIONS="rw,exec,nosuid,nodev,size=4g,mode=0700"
GO_BIN=''
GO_BIN_DIR=''
PG_BINDIR=''
PSQL_BIN=''
PODMAN_BIN=''
SUDO_BIN=/usr/bin/sudo
MOUNT_BIN=/usr/bin/mount
UMOUNT_BIN=/usr/bin/umount
FINDMNT_BIN=/usr/bin/findmnt

work_dir=''
run_dir=''
rootfs_dir=''
fetch_rootfs_dir=''
exec_artifacts_dir=''
exec_mountpoint=''
run_nonce=''
test_user=''
test_uid=''
test_gid=''
subid_range=''
subid_configured=0
db_name=''
db_role=''
password=''
firewall_chain=''
firewall_fetch_chain=''
rootfs_manifest_sha256=''
rootfs_library_path=''
fetch_manifest_sha256=''
statekit_artifact_digest=''
proxy_addresses_v4=()
proxy_addresses_v6=()
firewall4_created=0
firewall6_created=0
firewall_fetch4_created=0
firewall_fetch6_created=0
ipv6_allow6=''
db_role_reserved=0
cluster_started=0
cleanup_failed=0
artifact_created=0
workspace_nonce=''
workspace_cleaned=0
exec_mountpoint_created=0
exec_mount_mounted=0
test_command_timeout=300
build_container=''
fetch_container=''
mock_container=''
live_container=''
fetch_container_id=''
build_container_id=''
mock_container_id=''
live_container_id=''
podman_root=''
podman_runroot=''
podman_runtime=''
containers_cleaned=0
# R92T-INDEPENDENT-01 ownership receipt: records `id|name|phase|digest|nonce`
# for every container this run may remove. Populated only from a successful
# `podman create` return value or a fully verified partial-create reconcile.
container_receipt=()
rootfs_cleaned=0
fetch_rootfs_cleaned=0
exec_artifacts_cleaned=0
exec_mount_cleaned=0
identity_cleaned=0
# R92T-FRESH-01: monotonic destructive-teardown block. The moment any
# unowned, foreign, or unverifiable object is observed (candidate name
# collision, unknown Podman state, foreign/ambiguous partial create, or a
# missing/mismatched ownership receipt), both flags latch to 1 and are never
# cleared. While set, EXIT cleanup may remove only proven-owned resources and
# must not run cluster-wide stop, UID-wide process kill, user/subuid
# deletion, recursive store/rootfs/workdir removal, or tmpfs unmount: the
# identity, the private Podman store, the exec mount, the workspace, and the
# runner cluster's current state are preserved for investigation, no report
# artifact is published, and the run can only fail with a fixed class.
# Because every observation site fails the run immediately, no later phase
# can create against, inspect, or reuse the unowned object.
unowned_or_unknown_resource=0
destructive_teardown_blocked=0

bounded_timeout() {
  local seconds="$1"
  shift
  /usr/bin/timeout --signal=TERM --kill-after=5s "$seconds" "$@"
}

sudo_bounded() {
  bounded_timeout 30 "$SUDO_BIN" -n "$@"
}

fixed_error() {
  printf '%s\n' "$1" >&2
  exit 1
}

# R92T-FRESH-01: latch the destructive-teardown block (see the state
# comment above). Monotonic by construction: it only ever sets 1, so a later
# successful owned cleanup can never resume destructive teardown after an
# unowned observation.
mark_unowned_resource() {
  unowned_or_unknown_resource=1
  destructive_teardown_blocked=1
}

admin_psql() {
  bounded_timeout 30 "$SUDO_BIN" -n -u postgres -- /usr/bin/env -i \
      PATH=/usr/bin:/bin HOME=/var/lib/postgresql LC_ALL=C \
      "$PSQL_BIN" --no-psqlrc --no-password --username postgres \
      --dbname postgres --set=ON_ERROR_STOP=on "$@"
}

test_env_base=()

run_as_test_user() {
  local directory="$1"
  shift
  (
    cd "$directory"
    bounded_timeout "$test_command_timeout" "$SUDO_BIN" -n -- /usr/bin/setpriv \
      --reuid="$test_uid" --regid="$test_gid" --clear-groups \
      --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
      /usr/bin/env -i "${test_env_base[@]}" "$@"
  )
}

run_as_test_user_with_env() {
  local directory="$1" environment_name="$2"
  shift 2
  local -n environment="$environment_name"
  (
    cd "$directory"
    bounded_timeout "$test_command_timeout" "$SUDO_BIN" -n -- /usr/bin/setpriv \
      --reuid="$test_uid" --regid="$test_gid" --clear-groups \
      --no-new-privs --bounding-set=-all --inh-caps=-all --ambient-caps=-all -- \
      /usr/bin/env -i "${environment[@]}" "$@"
  )
}

preflight_exec_mount_plan() {
  [[ -x "$SUDO_BIN" && ! -L "$SUDO_BIN" \
     && -x "$MOUNT_BIN" && ! -L "$MOUNT_BIN" \
     && -x "$UMOUNT_BIN" && ! -L "$UMOUNT_BIN" \
     && -x "$FINDMNT_BIN" && ! -L "$FINDMNT_BIN" ]] || return 1
  run_nonce="$(/usr/bin/python3 -c 'import secrets; print(secrets.token_hex(10))')" || return 1
  [[ "$run_nonce" =~ ^[0-9a-f]{20}$ ]] || return 1
  workspace_nonce="$run_nonce"
  exec_mountpoint="/dev/shm/statekit-exec-$run_nonce"
  rootfs_dir="$exec_mountpoint/rootfs"
  /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 \
    tests/live/postgres/rootfs.py preflight-mount \
    --mountpoint "$exec_mountpoint" >/dev/null 2>&1 || return 1
  bounded_timeout 15 "$SUDO_BIN" -n -l -- "$MOUNT_BIN" -t tmpfs \
    -o "$EXEC_TMPFS_OPTIONS" tmpfs "$exec_mountpoint" >/dev/null 2>&1 || return 1
  bounded_timeout 15 "$SUDO_BIN" -n -l -- "$UMOUNT_BIN" -- \
    "$exec_mountpoint" >/dev/null 2>&1 || return 1
}

verify_exec_mount_identity() {
  [[ -n "$exec_mountpoint" && "$test_uid" =~ ^[1-9][0-9]*$ \
     && "$test_gid" =~ ^[0-9]+$ ]] || return 1
  run_as_test_user "$ROOT" /usr/bin/python3 \
    tests/live/postgres/rootfs.py verify-mount \
    --mountpoint "$exec_mountpoint" --uid "$test_uid" --gid "$test_gid" \
    >/dev/null 2>&1
}

create_exec_mount() {
  local mount_owner=''
  [[ "$exec_mountpoint" == "/dev/shm/statekit-exec-$workspace_nonce" \
     && "$workspace_nonce" =~ ^[0-9a-f]{20}$ \
     && ! -e "$exec_mountpoint" && ! -L "$exec_mountpoint" ]] || return 1
  mkdir -m 0700 -- "$exec_mountpoint" || return 1
  exec_mountpoint_created=1
  mount_owner="$(bounded_timeout 10 stat -c '%u:%g:%a' -- "$exec_mountpoint")" || return 1
  [[ "$mount_owner" == "$RUNNER_UID:$RUNNER_GID:700" ]] || return 1
  if ! bounded_timeout 30 "$SUDO_BIN" -n "$MOUNT_BIN" -t tmpfs \
      -o "$EXEC_TMPFS_OPTIONS" tmpfs "$exec_mountpoint" >/dev/null 2>&1; then
    return 1
  fi
  exec_mount_mounted=1
  sudo_bounded chown "$test_uid:$test_gid" "$exec_mountpoint" || return 1
  verify_exec_mount_identity
}

verify_postgres_admin_preflight() {
  local cluster_state='' effective='' listeners='' postgres_snapshot='' combined=''
  cluster_state="$(python3 tests/live/postgres/run.py --cluster-state)" || return 1
  effective="$(sudo_bounded -u postgres -- /usr/bin/env -i \
    PATH=/usr/bin:/bin HOME=/var/lib/postgresql LC_ALL=C \
    "$PG_BINDIR/postgres" -D /var/lib/postgresql/16/main \
    -c config_file=/etc/postgresql/16/main/postgresql.conf -C listen_addresses)" || return 1
  if ! /usr/bin/python3 -c '
import sys
addresses = [value.strip().strip("\047\"") for value in sys.stdin.read().strip().split(",")]
raise SystemExit(0 if addresses and all(value in {"localhost", "127.0.0.1", "::1"} for value in addresses) else 1)
' <<< "$effective"; then
    return 1
  fi
  listeners="$(sudo_bounded ss -H -ltnp sport = :5432)" || return 1
  case "$cluster_state" in
    down) [[ -z "$listeners" ]] ;;
    online)
      postgres_snapshot="$(sudo_bounded -u postgres -- /usr/bin/env -i \
        PATH=/usr/bin:/bin HOME=/var/lib/postgresql LC_ALL=C \
        /usr/bin/python3 - /var/lib/postgresql/16/main <<'PY'
import json
import os
from pathlib import Path
import pwd
import stat
import sys

data_dir = Path(sys.argv[1])
uid = pwd.getpwnam("postgres").pw_uid
if uid == 0 or data_dir.is_symlink() or not data_dir.is_dir() or data_dir.stat().st_uid != uid:
    raise SystemExit(1)
pidfile = data_dir / "postmaster.pid"
metadata = pidfile.lstat()
if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != uid or metadata.st_nlink != 1:
    raise SystemExit(1)
pid_data = pidfile.read_bytes()
if len(pid_data) > 4096:
    raise SystemExit(1)
lines = pid_data.decode("ascii", "strict").splitlines()
if len(lines) < 4 or not lines[0].isdecimal() or lines[1] != str(data_dir) or lines[3] != "5432":
    raise SystemExit(1)
pid = lines[0]
proc = Path("/proc") / pid
status = (proc / "status").read_text(encoding="ascii").splitlines()
uid_line = next(line for line in status if line.startswith("Uid:"))
uids = [int(value) for value in uid_line.split()[1:]]
executable = os.path.realpath(os.readlink(proc / "exe"))
cmdline = (proc / "cmdline").read_bytes()
if len(cmdline) > 65536:
    raise SystemExit(1)
argv = [value.decode("utf-8", "strict") for value in cmdline.split(b"\0") if value]
print(json.dumps({
    "pid_lines": lines[:4],
    "process": {"pid": pid, "uids": uids, "exe": executable, "argv": argv},
}, separators=(",", ":")))
PY
      )" || return 1
      combined="$(printf '%s\n%s' "$postgres_snapshot" "$listeners" | /usr/bin/python3 -c '
import json
import sys
snapshot = json.loads(sys.stdin.readline())
snapshot["listeners"] = sys.stdin.read()
print(json.dumps(snapshot, separators=(",", ":")))
')" || return 1
      printf '%s\n' "$combined" | /usr/bin/python3 tests/live/postgres/run.py --verify-server \
        >/dev/null 2>&1
      ;;
    *) return 1 ;;
  esac
}

podman_as_test_user() {
  # Rootless-bootstrap context only: the Podman client must exec the setuid
  # newuidmap/newgidmap helpers, so this wrapper must NOT impose
  # no-new-privileges or an empty capability bounding set. Payload containers
  # still get --cap-drop=ALL, no-new-privileges, and the in-rootfs preflight;
  # those are verified per container before every start.
  (( EUID != 0 && test_uid > 0 && test_gid > 0 )) || return 1
  bounded_timeout "$test_command_timeout" "$SUDO_BIN" -n -- /usr/bin/setpriv \
    --reuid="$test_uid" --regid="$test_gid" --clear-groups \
    -- \
    /usr/bin/env -i \
    "PATH=/usr/bin:/bin" "LC_ALL=C" "HOME=$run_dir/home" \
    "TMPDIR=$run_dir/tmp" "XDG_RUNTIME_DIR=$podman_runtime" \
    "XDG_CONFIG_HOME=$run_dir/podman-config" \
    "XDG_DATA_HOME=$run_dir/podman-data" \
    "XDG_CACHE_HOME=$run_dir/podman-cache" \
    "$PODMAN_BIN" --remote=false --root "$podman_root" \
    --runroot "$podman_runroot" --storage-driver=vfs "$@"
}

# SEC-01 tri-state: `podman container exists` distinguishes present (rc=0),
# absent (rc=1), and operational error (any other rc). No caller may collapse
# present/absent/unknown into one success value.
container_state() {
  local name="$1" rc=0
  podman_as_test_user container exists "$name" >/dev/null 2>&1 || rc=$?
  case "$rc" in
    0) printf 'present\n' ;;
    1) printf 'absent\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

# Reserve/create collision guard: only a proven-absent name may proceed;
# present or unknown fails closed. A present or unknown candidate name may
# be a foreign object, so this also latches the destructive-teardown block.
container_must_be_absent() {
  local observed=''
  [[ -n "$1" ]] || return 1
  observed="$(container_state "$1")"
  if [[ "$observed" == absent ]]; then
    return 0
  fi
  mark_unowned_resource
  return 1
}

# R92T-FRESH-01: the private run-scoped rootless store must be provably
# empty before the first create. Any listed object, or an operational error
# that leaves the store contents unverifiable, is foreign: the store is
# preserved untouched, the block latches, and the run fails before any
# container is created.
verify_container_store_empty() {
  local listing=''
  if ! listing="$(podman_as_test_user ps --all --quiet 2>/dev/null)"; then
    mark_unowned_resource
    return 1
  fi
  if [[ -n "${listing//[[:space:]]/}" ]]; then
    mark_unowned_resource
    return 1
  fi
}

# R92T-INDEPENDENT-01: a candidate container name is not ownership. The
# receipt is the sole record of containers this run may remove. Each record
# binds one canonical container ID returned by `podman create` to the
# immutable labels the container was created with: run nonce, phase, and
# rootfs manifest digest. Records live in a single array so every update is
# atomic: a claim is one append, a release is one whole-array reassignment,
# and the EXIT trap can only ever observe complete records.
readonly CONTAINER_OWNERSHIP_FORMAT='{{.Id}}|{{.Name}}|{{index .Config.Labels "io.statekit.run.nonce"}}|{{index .Config.Labels "io.statekit.phase"}}|{{index .Config.Labels "io.statekit.rootfs.manifest-sha256"}}'

container_id_is_canonical() {
  [[ "$1" =~ ^[0-9a-f]{64}$ ]]
}

# Claim one container into the ownership receipt. Fails closed on a
# non-canonical ID, an unknown phase, a digest that is not 64-hex, a nonce
# that is not this run's, a duplicate container ID or name, or a second
# record for a phase already held: a duplicate or cross-phase/cross-run
# receipt must never authorize removal. A created object whose receipt
# cannot be recorded is unowned, so a failed claim latches the
# destructive-teardown block before failing closed.
container_receipt_claim() {
  if container_receipt_claim_valid "$@"; then
    return 0
  fi
  mark_unowned_resource
  return 1
}

container_receipt_claim_valid() {
  local canonical_id="$1" name="$2" phase="$3" digest="$4" nonce="$5"
  local record='' held_id='' held_name='' held_phase=''
  [[ "$nonce" == "$run_nonce" && "$nonce" =~ ^[0-9a-f]{20}$ ]] || return 1
  container_id_is_canonical "$canonical_id" || return 1
  [[ -n "$name" && "$phase" =~ ^(fetch|build|mock|live)$ \
     && "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  if (( ${dig_contract_only:-0} == 1 )); then
    local identity='' gate=''
    identity="$(container_ownership_identity "$canonical_id")" || return 1
    [[ "$identity" == "$canonical_id|$name|$nonce|$phase|$digest" \
       || "$identity" == "$canonical_id|/$name|$nonce|$phase|$digest" ]] || return 1
    gate="$(podman_as_test_user inspect --format '{{index .Config.Labels "io.statekit.gate"}}' "$canonical_id")" || return 1
    [[ "$gate" == dig-contract ]] || return 1
  fi
  for record in "${container_receipt[@]}"; do
    IFS='|' read -r held_id held_name held_phase _ _ <<< "$record"
    [[ "$held_id" != "$canonical_id" && "$held_name" != "$name" \
       && "$held_phase" != "$phase" ]] || return 1
  done
  container_receipt+=("$canonical_id|$name|$phase|$digest|$nonce")
}

# Release one phase's record after its container is proven absent. The
# whole receipt is replaced in a single assignment.
container_receipt_release() {
  local phase="$1" record='' held_phase=''
  local -a kept=()
  for record in "${container_receipt[@]}"; do
    IFS='|' read -r _ _ held_phase _ _ <<< "$record"
    [[ "$held_phase" == "$phase" ]] && continue
    kept+=("$record")
  done
  container_receipt=("${kept[@]}")
}

# One inspect snapshot carries every ownership identity field for a
# selector (canonical ID or name). The output is untrusted: every field is
# revalidated by the caller against the receipt.
container_ownership_identity() {
  local selector="$1" line=''
  line="$(podman_as_test_user inspect --format "$CONTAINER_OWNERSHIP_FORMAT" \
    "$selector" 2>/dev/null)" || return 1
  [[ -n "$line" && "$line" != *[$'\n'$'\r']* ]] || return 1
  printf '%s\n' "$line"
}

# Remove exactly one receipt-held container: the live object is re-verified
# by canonical ID against the receipt's own immutable identity immediately
# before removal, removal addresses only the canonical ID, and absence is
# proven afterward. Already-proven absence is an idempotent success; an
# unknown existence, an unverifiable inspect, or any identity mismatch
# latches the destructive-teardown block and fails closed with the object
# preserved. Only a removal failure of the already-proven-owned object is an
# owned-cleanup failure rather than an unowned observation.
cleanup_owned_container() {
  local canonical_id="$1" name="$2" phase="$3" digest="$4" nonce="$5"
  local identity='' extra=''
  local seen_id='' seen_name='' seen_nonce='' seen_phase='' seen_digest=''
  [[ "$nonce" == "$run_nonce" ]] || return 1
  case "$(container_state "$canonical_id")" in
    absent) return 0 ;;
    present) ;;
    *) mark_unowned_resource; return 1 ;;
  esac
  identity="$(container_ownership_identity "$canonical_id")" \
    || { mark_unowned_resource; return 1; }
  IFS='|' read -r seen_id seen_name seen_nonce seen_phase seen_digest extra <<< "$identity"
  seen_name="${seen_name#/}"
  container_id_is_canonical "$seen_id" || { mark_unowned_resource; return 1; }
  [[ -z "$extra" && "$seen_id" == "$canonical_id" && "$seen_name" == "$name" \
     && "$seen_nonce" == "$nonce" && "$seen_phase" == "$phase" \
      && "$seen_digest" == "$digest" ]] || { mark_unowned_resource; return 1; }
  if (( ${dig_contract_only:-0} == 1 )); then
    [[ "$(podman_as_test_user inspect --format '{{index .Config.Labels "io.statekit.gate"}}' "$canonical_id")" == dig-contract ]] \
      || { mark_unowned_resource; return 1; }
  fi
  podman_as_test_user rm --force "$canonical_id" >/dev/null 2>&1 || return 1
  case "$(container_state "$canonical_id")" in
    absent) return 0 ;;
    *) mark_unowned_resource; return 1 ;;
  esac
}

# `podman create` returned nonzero but may still have partially created an
# object. Claim it only when the exact random candidate name resolves to a
# canonical container ID carrying this run's nonce, phase, and manifest
# digest. Returns 0 when the object was claimed into the receipt, 1 when
# nothing exists under the name (nothing to reconcile), and 2 when an
# object exists but ownership is unverifiable or ambiguous: the object is
# preserved untouched and the run fails with a fixed class instead of
# deleting a possible pre-existing resource.
reconcile_partial_create() {
  local name="$1" phase="$2" digest="$3"
  local identity='' extra=''
  local seen_id='' seen_name='' seen_nonce='' seen_phase='' seen_digest=''
  case "$(container_state "$name")" in
    absent) return 1 ;;
    present) ;;
    *) return 2 ;;
  esac
  identity="$(container_ownership_identity "$name")" || return 2
  IFS='|' read -r seen_id seen_name seen_nonce seen_phase seen_digest extra <<< "$identity"
  seen_name="${seen_name#/}"
  container_id_is_canonical "$seen_id" || return 2
  [[ -z "$extra" && "$seen_name" == "$name" && "$seen_nonce" == "$run_nonce" \
     && "$seen_phase" == "$phase" && "$seen_digest" == "$digest" ]] || return 2
  container_receipt_claim "$seen_id" "$seen_name" "$seen_phase" "$seen_digest" "$seen_nonce"
}

# Shared create-failure exit: a clean failure (or a fully reconciled
# partial object, which EXIT cleanup then removes by canonical ID) keeps
# the phase's own fixed class; an unverifiable partial object is preserved,
# latches the destructive-teardown block, and fails with a distinct fixed
# class.
create_failed_reconcile() {
  local name="$1" phase="$2" digest="$3" phase_error="$4" status=0
  if (( ${dig_contract_only:-0} == 1 )); then
    mark_unowned_resource
    fixed_error 'podman-create-partial-object-unowned'
  fi
  reconcile_partial_create "$name" "$phase" "$digest" || status=$?
  case "$status" in
    0|1) fixed_error "$phase_error" ;;
    *) mark_unowned_resource; fixed_error 'podman-create-partial-object-unowned' ;;
  esac
}

verify_containers_absent() {
  # Terminal teardown proof survives account deletion; never call Podman
  # again once this stage has completed. Only receipt-held canonical IDs
  # are proven absent: an object that merely shares a candidate name is
  # foreign and must neither be removed nor block this run's teardown.
  (( containers_cleaned == 0 )) || return 0
  local record='' canonical_id=''
  for record in "${container_receipt[@]}"; do
    canonical_id="${record%%|*}"
    container_must_be_absent "$canonical_id" || return 1
  done
}

cleanup_all_containers() {
  (( containers_cleaned == 0 )) || return 0
  local record='' failed=0
  local canonical_id='' name='' phase='' digest='' nonce=''
  for record in "${container_receipt[@]}"; do
    IFS='|' read -r canonical_id name phase digest nonce <<< "$record"
    cleanup_owned_container "$canonical_id" "$name" "$phase" "$digest" "$nonce" \
      || failed=1
  done
  (( failed == 0 )) || return 1
  verify_containers_absent || return 1
  containers_cleaned=1
}

# Mid-run per-phase cleanup (dependency fetch): remove and release exactly
# the phase's receipt record; a phase that was never claimed is an error.
cleanup_phase_container() {
  local phase="$1" record='' found=0
  local canonical_id='' name='' held_phase='' digest='' nonce=''
  for record in "${container_receipt[@]}"; do
    IFS='|' read -r canonical_id name held_phase digest nonce <<< "$record"
    [[ "$held_phase" == "$phase" ]] || continue
    cleanup_owned_container "$canonical_id" "$name" "$held_phase" "$digest" "$nonce" \
      || return 1
    container_receipt_release "$phase"
    found=1
    break
  done
  (( found == 1 ))
}

verify_podman_container() {
  local name="$1" network="$2" env_names_name="$3" binds_name="$4"
  local expected_rootfs="$5" expected_manifest="$6" tmpfs_size="${7:-2g}"
  local -n env_names="$env_names_name" bind_specs="$binds_name"
  local inspect_json='' policy_args=() bind='' env_name=''
  if (( ${dig_contract_only:-0} == 1 )); then
    local cgroup_mode=''
    cgroup_mode="$(podman_as_test_user inspect --format '{{.HostConfig.Cgroups}}' "$name")" || return 1
    [[ "$cgroup_mode" == enabled ]] || return 1
  fi
  [[ -n "$expected_rootfs" && "$expected_manifest" =~ ^[0-9a-f]{64}$ ]] || return 1
  verify_exec_mount_identity || return 1
  inspect_json="$(podman_as_test_user inspect --format '{{json .}}' "$name")" || return 1
  policy_args=(
    --user "$test_uid:$test_gid" --network "$network"
    --rootfs "$expected_rootfs"
    --manifest-sha256 "$expected_manifest"
    --memory "$((4 * 1024 * 1024 * 1024))" --nano-cpus 2000000000
    --pids 256 --tmpfs "/tmp=rw,nosuid,nodev,size=$tmpfs_size,mode=1777"
    --tmpfs "/dev/shm=rw,nosuid,nodev,noexec,size=64m,mode=1777"
  )
  for bind in "${bind_specs[@]}"; do policy_args+=(--bind "$bind"); done
  for env_name in "${env_names[@]}"; do policy_args+=(--env-name "$env_name"); done
  local result=0
  # Source and target metadata live below test-UID-owned mode-0700 parents.
  # Inspect them as that UID, retaining the payload wrapper's NNP/cap limits.
  if printf '%s\n' "$inspect_json" | run_as_test_user "$ROOT" \
      /usr/bin/python3 tests/live/postgres/podman_policy.py \
      "${policy_args[@]}" >/dev/null 2>&1; then
    result=0
  else
    result=$?
  fi
  inspect_json=''
  return "$result"
}

verify_rootless_podman() {
  local rootless='' graph_root='' run_root=''
  rootless="$(podman_as_test_user info --format '{{.Host.Security.Rootless}}')" || return 1
  graph_root="$(podman_as_test_user info --format '{{.Store.GraphRoot}}')" || return 1
  run_root="$(podman_as_test_user info --format '{{.Store.RunRoot}}')" || return 1
  [[ "$rootless" == true && "$graph_root" == "$podman_root" \
     && "$run_root" == "$podman_runroot" ]]
}

verify_rootless_helpers() {
  # SEC-04: the setuid subordinate-mapping helpers must be the exact OS
  # binaries, root-owned, setuid, and not group/other writable. They run
  # without the payload NNP restriction by design (see podman_as_test_user).
  local tool='' metadata='' owner='' group='' mode_bits='' shadow_gid=''
  shadow_gid="$(bounded_timeout 10 getent group shadow | cut -d: -f3)" || shadow_gid=''
  [[ "$shadow_gid" =~ ^[0-9]+$ ]] || shadow_gid=0
  for tool in /usr/bin/newuidmap /usr/bin/newgidmap; do
    [[ -x "$tool" && ! -L "$tool" ]] || return 1
    metadata="$(bounded_timeout 10 stat -c '%u:%g:%a' -- "$tool")" || return 1
    IFS=: read -r owner group mode_bits <<< "$metadata"
    [[ "$owner" == 0 && ( "$group" == 0 || "$group" == "$shadow_gid" ) ]] || return 1
    [[ "$mode_bits" == 4755 || "$mode_bits" == 4754 ]] || return 1
  done
}

verify_rootfs_authoritative() {
  # SEC-02: independently revalidate the manifest and the entire staged tree
  # immediately before create/start. Never executed against labels alone.
  local directory="$1" profile="$2" digest="$3"
  if (( ${dig_contract_only:-0} == 1 )) && [[ "$profile" == live-executable ]]; then
    profile=dig-contract
  fi
  [[ -n "$directory" && -n "$profile" && "$digest" =~ ^[0-9a-f]{64}$ ]] || return 1
  verify_exec_mount_identity || return 1
  run_as_test_user "$ROOT" /usr/bin/python3 tests/live/postgres/rootfs.py verify \
    --destination "$directory" --manifest-sha256 "$digest" \
    --profile "$profile" --exec-mount "$exec_mountpoint" >/dev/null 2>&1
}

# Remove one verified exec-mount child tree (rootfs or rootfs-fetch). The
# staged manifest profile must match the expected one before any removal.
remove_rootfs_tree() {
  local tree_dir="$1" expected_profile="$2"
  if (( ${dig_contract_only:-0} == 1 )) && [[ "$expected_profile" == live-executable ]]; then
    expected_profile=dig-contract
  fi
  local metadata='' manifest='' profile=''
  [[ -n "$tree_dir" ]] || return 0
  if ! sudo_bounded test -e "$tree_dir" \
       && ! sudo_bounded test -L "$tree_dir"; then
    return 0
  fi
  [[ "$tree_dir" == "$exec_mountpoint/rootfs" \
     || "$tree_dir" == "$exec_mountpoint/rootfs-fetch" ]] \
    && [[ "$exec_mountpoint" == "/dev/shm/statekit-exec-$workspace_nonce" \
     && ! -L /dev/shm ]] || return 1
  run_as_test_user "$ROOT" /usr/bin/test -d "$tree_dir" \
    && ! run_as_test_user "$ROOT" /usr/bin/test -L "$tree_dir" || return 1
  verify_exec_mount_identity || return 1
  metadata="$(run_as_test_user "$ROOT" /usr/bin/stat -c '%u:%g:%a' -- "$tree_dir")" || return 1
  [[ "$metadata" == "$test_uid:$test_gid:755" ]] || return 1
  manifest="$tree_dir/etc/statekit-rootfs.manifest"
  run_as_test_user "$ROOT" /usr/bin/test -f "$manifest" \
    && ! run_as_test_user "$ROOT" /usr/bin/test -L "$manifest" || return 1
  profile="$(run_as_test_user "$ROOT" /usr/bin/python3 - "$manifest" <<'PY'
import json
from pathlib import Path
import sys

try:
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, ValueError, UnicodeError):
    raise SystemExit(1)
print(manifest.get("runtime_profile") or "")
PY
)" || return 1
  [[ "$profile" == "$expected_profile" ]] || return 1
  run_as_test_user "$ROOT" /usr/bin/rm -rf --one-file-system -- "$tree_dir" || return 1
  ! run_as_test_user "$ROOT" /usr/bin/test -e "$tree_dir" \
    && ! run_as_test_user "$ROOT" /usr/bin/test -L "$tree_dir"
}

remove_rootfs() {
  remove_rootfs_tree "$rootfs_dir" live-executable
}

remove_fetch_rootfs() {
  remove_rootfs_tree "$fetch_rootfs_dir" dependency-fetch
}

remove_exec_artifacts() {
  # SEC-05: the compiled artifact lives in the verified exec tmpfs; removal
  # proves the artifacts child is gone before the mount itself is unmounted.
  local artifacts_dir="$exec_artifacts_dir"
  [[ -n "$artifacts_dir" ]] || return 0
  if ! sudo_bounded test -e "$artifacts_dir" \
       && ! sudo_bounded test -L "$artifacts_dir"; then
    return 0
  fi
  [[ "$artifacts_dir" == "$exec_mountpoint/artifacts" \
     && "$exec_mountpoint" == "/dev/shm/statekit-exec-$workspace_nonce" \
     && ! -L /dev/shm ]] || return 1
  verify_exec_mount_identity || return 1
  run_as_test_user "$ROOT" /usr/bin/rm -rf --one-file-system -- "$artifacts_dir" || return 1
  ! run_as_test_user "$ROOT" /usr/bin/test -e "$artifacts_dir" \
    && ! run_as_test_user "$ROOT" /usr/bin/test -L "$artifacts_dir"
}

remove_exec_mount() {
  local target='' rc=0
  [[ -n "$exec_mountpoint" \
     && "$exec_mountpoint" == "/dev/shm/statekit-exec-$workspace_nonce" \
     && "$workspace_nonce" =~ ^[0-9a-f]{20}$ ]] || return 1
  verify_containers_absent || return 1
  local tree=''
  for tree in "$rootfs_dir" "$fetch_rootfs_dir" "$exec_artifacts_dir"; do
    if [[ -n "$tree" ]] && \
         { sudo_bounded test -e "$tree" || sudo_bounded test -L "$tree"; }; then
      return 1
    fi
  done
  target="$(bounded_timeout 10 "$FINDMNT_BIN" --vfs-all --noheadings --raw \
    --output TARGET --mountpoint "$exec_mountpoint" 2>/dev/null)" || rc=$?
  if (( rc == 0 )); then
    [[ "$target" == "$exec_mountpoint" && "$exec_mountpoint_created" == 1 ]] || return 1
    run_as_test_user "$ROOT" /usr/bin/python3 tests/live/postgres/rootfs.py \
      verify-cleanup --mountpoint "$exec_mountpoint" \
      --uid "$test_uid" --gid "$test_gid" >/dev/null 2>&1 || return 1
    bounded_timeout 30 "$SUDO_BIN" -n "$UMOUNT_BIN" -- \
      "$exec_mountpoint" >/dev/null 2>&1 || return 1
    /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 \
      tests/live/postgres/rootfs.py finish-cleanup \
      --mountpoint "$exec_mountpoint" \
      --runner-uid "$RUNNER_UID" --runner-gid "$RUNNER_GID" \
      >/dev/null 2>&1 || return 1
    exec_mount_mounted=0
    exec_mountpoint_created=0
  elif (( rc == 1 )) && [[ -z "$target" ]]; then
    if (( exec_mountpoint_created == 1 )); then
      /usr/bin/env -i PATH=/usr/bin:/bin LC_ALL=C /usr/bin/python3 \
        tests/live/postgres/rootfs.py finish-cleanup \
        --mountpoint "$exec_mountpoint" \
        --runner-uid "$RUNNER_UID" --runner-gid "$RUNNER_GID" \
        >/dev/null 2>&1 || return 1
      exec_mountpoint_created=0
    elif [[ -e "$exec_mountpoint" || -L "$exec_mountpoint" ]]; then
      return 1
    fi
    exec_mount_mounted=0
  else
    return 1
  fi
  [[ "$exec_mountpoint_created" == 0 && "$exec_mount_mounted" == 0 \
     && ! -e "$exec_mountpoint" && ! -L "$exec_mountpoint" ]]
}

cleanup_exec_files() {
  # Both the success path and EXIT use these stage receipts. A failed stage
  # retains the UID and mount for retry; later stages must not run through it.
  (( containers_cleaned == 1 )) || return 1
  if (( rootfs_cleaned == 0 )); then
    remove_rootfs || return 1
    rootfs_cleaned=1
  fi
  if (( fetch_rootfs_cleaned == 0 )); then
    remove_fetch_rootfs || return 1
    fetch_rootfs_cleaned=1
  fi
  if (( exec_artifacts_cleaned == 0 )); then
    remove_exec_artifacts || return 1
    exec_artifacts_cleaned=1
  fi
  if (( exec_mount_cleaned == 0 )); then
    if [[ -n "$exec_mountpoint" ]]; then
      remove_exec_mount || return 1
    fi
    exec_mount_cleaned=1
  fi
}

workspace_identity_matches() {
  local path="$1" expected_nonce="$2" expected_owner="$3"
  local pattern="^/dev/shm/statekit-pg-${expected_nonce}\\.[A-Za-z0-9]{8}$"
  local actual_owner=''
  [[ "$expected_nonce" =~ ^[0-9a-f]{20}$ && "$expected_owner" =~ ^[0-9]+$ ]] || return 1
  [[ "$path" =~ $pattern && ! -L /dev/shm && -d "$path" && ! -L "$path" ]] || return 1
  actual_owner="$(bounded_timeout 10 stat -c '%u' -- "$path")" || return 1
  [[ "$actual_owner" == "$expected_owner" ]]
}

cleanup_workspace() {
  local path="$1" expected_nonce="$2" expected_owner="$3" privileged="${4:-1}"
  local remove_rc=0
  workspace_identity_matches "$path" "$expected_nonce" "$expected_owner" || return 1
  if [[ "$privileged" == 1 ]]; then
    sudo_bounded rm -rf --one-file-system -- "$path" || remove_rc=$?
  else
    bounded_timeout 15 rm -rf --one-file-system -- "$path" || remove_rc=$?
  fi
  [[ ! -e "$path" && ! -L "$path" && "$remove_rc" == 0 ]]
}

workspace_self_test() {
  local self_nonce='' self_path='' owner='' wrong_prefix='' wrong_suffix=''
  [[ "$EUID" != 0 ]] || fixed_error 'workspace-test-requires-nonroot'
  self_nonce="$(python3 -c 'import secrets; print(secrets.token_hex(10))')" || \
    fixed_error 'workspace-test-nonce-failed'
  [[ "$self_nonce" =~ ^[0-9a-f]{20}$ ]] || fixed_error 'workspace-test-nonce-failed'
  self_path="$(bounded_timeout 10 mktemp -d "/dev/shm/statekit-pg-${self_nonce}.XXXXXXXX")" || \
    fixed_error 'workspace-test-create-failed'
  owner="$(bounded_timeout 10 id -u)" || fixed_error 'workspace-test-owner-failed'
  workspace_identity_matches "$self_path" "$self_nonce" "$owner" || \
    fixed_error 'workspace-test-identity-failed'
  : > "$self_path/residual-probe"
  wrong_prefix="${self_path/statekit-pg/not-statekit-pg}"
  wrong_suffix="${self_path}x"
  if workspace_identity_matches "$wrong_prefix" "$self_nonce" "$owner" || \
     workspace_identity_matches "$wrong_suffix" "$self_nonce" "$owner" || \
     workspace_identity_matches "$self_path" "$self_nonce" "$((owner + 1))"; then
    cleanup_workspace "$self_path" "$self_nonce" "$owner" 0 || true
    fixed_error 'workspace-test-guard-accepted-mismatch'
  fi
  cleanup_workspace "$wrong_suffix" "$self_nonce" "$owner" 0 && \
    fixed_error 'workspace-test-cleanup-accepted-mismatch'
  [[ -d "$self_path" && ! -L "$self_path" ]] || fixed_error 'workspace-test-mismatch-mutated-path'
  cleanup_workspace "$self_path" "$self_nonce" "$owner" 0 || \
    fixed_error 'workspace-test-cleanup-failed'
  [[ ! -e "$self_path" && ! -L "$self_path" ]] || fixed_error 'workspace-test-residual-path'
}

remove_firewall_family() {
  local binary="$1" created="$2" chain="${3:-$firewall_chain}"
  local rc=0 attempt=0
  (( created == 1 )) || return 0
  for (( attempt=0; attempt<8; attempt++ )); do
    if sudo_bounded "$binary" -C OUTPUT -m owner --uid-owner "$test_uid" \
        -j "$chain" >/dev/null 2>&1; then
      sudo_bounded "$binary" -D OUTPUT -m owner --uid-owner "$test_uid" \
        -j "$chain" >/dev/null 2>&1 || return 1
    else
      rc=$?
      (( rc == 1 )) || return 1
      break
    fi
  done
  if (( attempt == 8 )); then
    return 1
  fi
  if sudo_bounded "$binary" -S "$chain" >/dev/null 2>&1; then
    sudo_bounded "$binary" -F "$chain" >/dev/null 2>&1 || return 1
    sudo_bounded "$binary" -X "$chain" >/dev/null 2>&1 || return 1
  else
    rc=$?
    (( rc == 1 )) || return 1
  fi
  if sudo_bounded "$binary" -C OUTPUT -m owner --uid-owner "$test_uid" \
      -j "$chain" >/dev/null 2>&1; then
    return 1
  else
    rc=$?
    (( rc == 1 )) || return 1
  fi
  if sudo_bounded "$binary" -S "$chain" >/dev/null 2>&1; then
    return 1
  else
    rc=$?
    (( rc == 1 )) || return 1
  fi
  return 0
}

firewall_chain_is_absent() {
  local binary="$1" chain="${2:-$firewall_chain}" rc=0
  if sudo_bounded "$binary" -S "$chain" >/dev/null 2>&1; then
    return 1
  else
    rc=$?
    (( rc == 1 ))
  fi
}

# SEC-03: firewall rules are verified with a canonical structured parser.
# `iptables -S` serializes `-p tcp --dport` as `-p tcp -m tcp --dport` and
# bare addresses as `/32` or `/128` suffixes, so raw string comparison is
# unreliable. The parser normalizes both sides and requires the exact
# ordered owned chain (rejecting any extra ACCEPT/RETURN/bypass, wrong
# DNS/proxy address, source, or port) plus exactly one first-position
# owner jump in OUTPUT.
firewall_parser_program() {
  local parser_line=''
  while IFS= read -r parser_line || [[ -n "$parser_line" ]]; do
    printf '%s\n' "$parser_line"
  done <<'PY'
import ipaddress
import os
import sys


def fail():
    raise SystemExit(1)


def normalize_address(value):
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        fail()
    if network.num_addresses != 1:
        fail()
    return str(network.network_address)


def accept_rule(destination, protocol, port, interface=None):
    return {
        "proto": protocol, "dport": port, "dest": destination,
        "source": None, "out": interface, "uid": None, "target": "ACCEPT",
        "reject": None,
    }


DROP_RULE = {
    "proto": None, "dport": None, "dest": None,
    "source": None, "out": None, "uid": None, "target": "DROP",
    "reject": None,
}


def reject_rule(destination, port):
    # R92T-BACKEND-FINAL-01: the only permitted REJECT shape is one exact
    # owner-scoped tcp-reset refusal for the unavailable loopback endpoint.
    # It synthesizes a deterministic connection-refused response without
    # permitting any listener and without opening any non-loopback
    # destination; port 5433 is never accepted and stays loopback-only.
    return {
        "proto": "tcp", "dport": port, "dest": destination,
        "source": None, "out": "lo", "uid": None, "target": "REJECT",
        "reject": "tcp-reset",
    }


def parse_rule(line, chain):
    fields = line.split()
    if not fields:
        fail()
    action = fields[0]
    if action == "-N":
        if fields[1:] != [chain]:
            fail()
        return ("chain", None)
    if action == "-P":
        if len(fields) != 3 or fields[1] != chain:
            fail()
        return ("policy", fields[2])
    if action != "-A" or len(fields) < 3 or fields[1] != chain:
        fail()
    rule = {
        "proto": None, "dport": None, "dest": None,
        "source": None, "out": None, "uid": None, "target": None,
        "reject": None,
    }
    module = False
    owner_module = False
    index = 2
    while index < len(fields):
        token = fields[index]
        value = fields[index + 1] if index + 1 < len(fields) else ""
        if token == "-p" and value in ("tcp", "udp") and rule["proto"] is None:
            rule["proto"] = value
            index += 2
        elif token == "-m" and value in ("tcp", "udp"):
            if module or (rule["proto"] not in (None, value)):
                fail()
            module = True
            index += 2
        elif token == "-m" and value == "owner":
            if owner_module:
                fail()
            owner_module = True
            index += 2
        elif token == "--dport" and value.isdecimal() and rule["dport"] is None:
            rule["dport"] = value
            index += 2
        elif token in ("-d", "--destination") and rule["dest"] is None:
            rule["dest"] = normalize_address(value)
            index += 2
        elif token in ("-s", "--source") and rule["source"] is None:
            rule["source"] = normalize_address(value)
            index += 2
        elif token == "-o" and value == "lo" and rule["out"] is None:
            rule["out"] = "lo"
            index += 2
        elif token == "--uid-owner" and value.isdecimal() and rule["uid"] is None:
            rule["uid"] = value
            index += 2
        elif token == "-j" and value and rule["target"] is None:
            rule["target"] = value
            index += 2
        elif (token == "--reject-with" and value == "tcp-reset"
              and rule["reject"] is None and rule["target"] == "REJECT"):
            rule["reject"] = value
            index += 2
        else:
            fail()
    if rule["dport"] is not None and rule["proto"] is None:
        fail()
    if owner_module and rule["uid"] is None:
        fail()
    if rule["target"] == "REJECT" and rule["reject"] != "tcp-reset":
        fail()
    if rule["reject"] is not None and rule["target"] != "REJECT":
        fail()
    return ("rule", rule)


mode = os.environ.get("FWC_MODE", "")
chain = os.environ.get("FWC_CHAIN", "")
uid = os.environ.get("FWC_UID", "")
dns = os.environ.get("FWC_DNS", "")
allow = [item for item in os.environ.get("FWC_ALLOW", "").split(",") if item]
reject = [item for item in os.environ.get("FWC_REJECT", "").split(",") if item]
if mode not in ("fetch", "live") or not chain or not uid.isdecimal():
    fail()
expected = [("chain", None)]
if mode == "fetch":
    if not dns or reject:
        fail()
    resolver = normalize_address(dns)
    expected.append(("rule", accept_rule(resolver, "udp", "53", "lo")))
    expected.append(("rule", accept_rule(resolver, "tcp", "53", "lo")))
    for address in allow:
        expected.append(("rule", accept_rule(normalize_address(address), "tcp", "443")))
else:
    if len(allow) > 1 or len(reject) > 1:
        fail()
    for address in allow:
        expected.append(("rule", accept_rule(normalize_address(address), "tcp", "5432", "lo")))
    for address in reject:
        expected.append(("rule", reject_rule(normalize_address(address), "5433")))
expected.append(("rule", dict(DROP_RULE)))
text = sys.stdin.read()
if len(text) > (64 << 10):
    fail()
sections = text.split("===OUTPUT===\n", 1)
if len(sections) != 2:
    fail()
parsed_chain = [parse_rule(line, chain)
                for line in sections[0].splitlines() if line.strip()]
parsed_output = [parse_rule(line, "OUTPUT")
                for line in sections[1].splitlines() if line.strip()]
if parsed_chain != expected:
    fail()
if not parsed_output or parsed_output[0][0] != "policy":
    fail()
jump = {
    "proto": None, "dport": None, "dest": None,
    "source": None, "out": None, "uid": uid, "target": chain,
    "reject": None,
}
rules = parsed_output[1:]
if not rules or rules[0] != ("rule", jump):
    fail()
if sum(1 for kind, rule in rules
       if kind == "rule" and rule.get("target") == chain) != 1:
    fail()
PY
}

firewall_policy_text() {
  local binary="$1" chain="$2" chain_text='' output_text=''
  chain_text="$(sudo_bounded "$binary" -S "$chain")" || return 1
  output_text="$(sudo_bounded "$binary" -S OUTPUT)" || return 1
  printf '%s\n===OUTPUT===\n%s\n' "$chain_text" "$output_text"
}

# Exact ordered policy check for one family's dependency-fetch chain. An
# empty pinned-address list is valid: the chain then allows only the exact
# configured loopback resolver and drops everything else.
verify_effective_fetch_firewall_family() {
  local binary="$1" dns_address="$2" address='' allow_joined=''
  shift 2
  for address; do
    allow_joined+="${allow_joined:+,}$address"
  done
  firewall_policy_text "$binary" "$firewall_fetch_chain" | \
    FWC_MODE=fetch FWC_CHAIN="$firewall_fetch_chain" FWC_UID="$test_uid" \
    FWC_DNS="$dns_address" FWC_ALLOW="$allow_joined" \
    /usr/bin/python3 -c "$(firewall_parser_program)"
}

# Exact ordered policy check for one family's live chain. An empty allow
# address (no IPv6 loopback listener) means the chain has no ACCEPT rule
# and drops every packet for the test UID. `reject_address` carries the
# unavailable loopback endpoint when this family owns one; an empty value
# (the IPv6 family: no case dials ::1:5433) means no REJECT rule at all,
# and any injected one fails verification.
verify_effective_live_firewall_family() {
  local binary="$1" allow_address="$2" reject_address="$3"
  firewall_policy_text "$binary" "$firewall_chain" | \
    FWC_MODE=live FWC_CHAIN="$firewall_chain" FWC_UID="$test_uid" \
    FWC_ALLOW="$allow_address" FWC_REJECT="$reject_address" \
    /usr/bin/python3 -c "$(firewall_parser_program)"
}

# Install one family's dependency-fetch chain. Chain ownership is recorded
# the moment `-N` succeeds, so any later failure (rule append or the OUTPUT
# hook insert) still leaves cleanup fully informed.
install_fetch_firewall_family() {
  local binary="$1" dns_address="$2" created_flag="$3"
  shift 3
  local -n fetch_created="$created_flag"
  local address=''
  firewall_chain_is_absent "$binary" "$firewall_fetch_chain" || return 1
  sudo_bounded "$binary" -N "$firewall_fetch_chain" >/dev/null 2>&1 || return 1
  fetch_created=1
  sudo_bounded "$binary" -A "$firewall_fetch_chain" -o lo -d "$dns_address" \
    -p udp --dport 53 -j ACCEPT >/dev/null 2>&1 || return 1
  sudo_bounded "$binary" -A "$firewall_fetch_chain" -o lo -d "$dns_address" \
    -p tcp --dport 53 -j ACCEPT >/dev/null 2>&1 || return 1
  for address in "$@"; do
    sudo_bounded "$binary" -A "$firewall_fetch_chain" -d "$address" \
      -p tcp --dport 443 -j ACCEPT >/dev/null 2>&1 || return 1
  done
  sudo_bounded "$binary" -A "$firewall_fetch_chain" \
    -j DROP >/dev/null 2>&1 || return 1
  sudo_bounded "$binary" -I OUTPUT 1 -m owner --uid-owner "$test_uid" \
    -j "$firewall_fetch_chain" >/dev/null 2>&1 || return 1
}

# Install one family's live chain. Both families are installed
# unconditionally; when the service does not bind IPv6 loopback the IPv6
# chain contains no ACCEPT rule and drops all test-UID traffic.
# R92T-BACKEND-FINAL-01: the unavailable-endpoint case dials exactly
# 127.0.0.1:5433, so the IPv4 chain carries one exact owner-scoped
# `REJECT --reject-with tcp-reset` rule for that loopback endpoint ahead
# of the terminal DROP. The kernel-synthesized RST makes the
# connection-refused outcome deterministic for both the native psql and
# StateKit refusal classifications without permitting an untrusted
# service/listener and without opening any non-loopback destination: 5433
# is never ACCEPTed, PostgreSQL stays allowed only on loopback:5432, and
# every other address and port remains DROP. No case dials ::1:5433, so
# the IPv6 chain never carries a 5433 rule.
install_live_firewall_family() {
  local binary="$1" created_flag="$2" allow_address="$3" reject_address="$4"
  local -n live_created="$created_flag"
  firewall_chain_is_absent "$binary" "$firewall_chain" || return 1
  sudo_bounded "$binary" -N "$firewall_chain" >/dev/null 2>&1 || return 1
  live_created=1
  if [[ -n "$allow_address" ]]; then
    sudo_bounded "$binary" -A "$firewall_chain" -o lo -d "$allow_address" \
      -p tcp --dport 5432 -j ACCEPT >/dev/null 2>&1 || return 1
  fi
  if [[ -n "$reject_address" ]]; then
    sudo_bounded "$binary" -A "$firewall_chain" -o lo -d "$reject_address" \
      -p tcp --dport 5433 -j REJECT --reject-with tcp-reset \
      >/dev/null 2>&1 || return 1
  fi
  sudo_bounded "$binary" -A "$firewall_chain" \
    -j DROP >/dev/null 2>&1 || return 1
  sudo_bounded "$binary" -I OUTPUT 1 -m owner --uid-owner "$test_uid" \
    -j "$firewall_chain" >/dev/null 2>&1 || return 1
}

postgres_binds_ipv6_loopback() {
  local listeners=''
  listeners="$(sudo_bounded ss -H -ltnp sport = :5432)" || return 1
  bounded_timeout 10 grep -Fq '[::1]:5432' <<<"$listeners"
}

# SEC-03: the only network-enabled phase is a fixed `go mod download` inside
# its own manifest-closed rootfs container. Egress for the test UID is
# allowlisted to the loopback resolver and the pinned public Go proxy,
# checksum-service, and module-storage addresses; everything else is
# dropped. Addresses are resolved once by the controller and pinned for the
# fetch; rotation during a run fails closed.
resolve_fetch_endpoints() {
  local -a lines=()
  mapfile -t lines < <(python3 - <<'PY'
import ipaddress
import socket
import sys

addresses = {"v4": [], "v6": []}
for host in ("proxy.golang.org", "sum.golang.org", "storage.googleapis.com"):
    for family, label in ((socket.AF_INET, "v4"), (socket.AF_INET6, "v6")):
        try:
            entries = socket.getaddrinfo(host, 443, family, socket.SOCK_STREAM)
        except OSError:
            entries = []
        for entry in entries:
            try:
                address = ipaddress.ip_address(entry[4][0])
            except ValueError:
                continue
            if address.is_global:
                addresses[label].append(str(address))
for label in ("v4", "v6"):
    values = sorted(set(addresses[label]))
    if label == "v4" and not values:
        raise SystemExit(1)
    for value in values:
        print(f"{label} {value}")
PY
  ) || return 1
  local line='' family='' address=''
  for line in "${lines[@]}"; do
    read -r family address <<< "$line"
    case "$family" in
      v4) proxy_addresses_v4+=("$address") ;;
      v6) proxy_addresses_v6+=("$address") ;;
      *) return 1 ;;
    esac
  done
  (( ${#proxy_addresses_v4[@]} > 0 )) || return 1
}

cleanup_database_and_role() {
  (( ${dig_contract_only:-0} == 0 )) || return 0
  local remaining=''
  (( db_role_reserved == 1 )) || return 0
  if ! admin_psql --quiet --tuples-only --no-align >/dev/null 2>&1 <<SQL
SELECT pg_terminate_backend(pid)
  FROM pg_stat_activity
 WHERE datname = '$db_name' AND pid <> pg_backend_pid();
DROP DATABASE IF EXISTS "$db_name";
DROP ROLE IF EXISTS "$db_role";
SQL
  then
    cleanup_failed=1
    return 1
  fi
  if ! remaining="$(admin_psql --quiet --tuples-only --no-align 2>/dev/null <<SQL
SELECT (SELECT count(*) FROM pg_database WHERE datname='$db_name') + (SELECT count(*) FROM pg_roles WHERE rolname='$db_role');
SQL
)" || [[ "$remaining" != 0 ]]; then
    cleanup_failed=1
    return 1
  fi
  db_role_reserved=0
}

# R92T-FRESH-01: restore the cluster state this run changed (stop 16/main
# only when this run started it), but never while the destructive-teardown
# block is latched. `cluster_started` records a startup attempt, not
# exclusive ownership of every database and client on the runner cluster,
# so a cluster-wide stop is outside the receipt-held canonical container ID
# and run-named firewall/DB-role cleanup allowlist: under the latch the
# helper is a no-op that reports only the fixed value-free class below and
# leaves the cluster in its current state for investigation.
cleanup_cluster() {
  (( ${dig_contract_only:-0} == 0 )) || return 0
  (( cluster_started == 1 )) || return 0
  if (( destructive_teardown_blocked == 1 || unowned_or_unknown_resource == 1 )); then
    printf '%s\n' 'cluster-stop-skipped-unowned-resource' >&2
    return 0
  fi
  if ! sudo_bounded pg_ctlcluster 16 main stop >/dev/null 2>&1; then
    cleanup_failed=1
    return 1
  fi
  if ! bounded_timeout 60 python3 tests/live/postgres/run.py --assert-cluster-down \
      >/dev/null 2>&1; then
    cleanup_failed=1
    return 1
  fi
  cluster_started=0
}

stop_test_user_processes() {
  [[ -n "$test_uid" ]] || return 0
  [[ "$test_uid" =~ ^[1-9][0-9]*$ ]] || { cleanup_failed=1; return 1; }
  sudo_bounded pkill -KILL -u "$test_uid" >/dev/null 2>&1 || true
  if bounded_timeout 10 pgrep -u "$test_uid" >/dev/null 2>&1; then
    cleanup_failed=1
    return 1
  else
    local rc=$?
    if (( rc != 1 )); then
      cleanup_failed=1
      return 1
    fi
  fi
}

cleanup_identity_and_files() {
  (( identity_cleaned == 0 )) || return 0
  if (( containers_cleaned != 1 || exec_mount_cleaned != 1 \
        || firewall4_created != 0 || firewall6_created != 0 \
        || firewall_fetch4_created != 0 || firewall_fetch6_created != 0 )); then
    cleanup_failed=1
    return 1
  fi
  local passwd_record='' group_record='' current_gid='' rc=0
  local record_name='' record_uid='' record_gid='' record_home='' record_shell=''
  local group_name='' group_members='' identity_absent=1
  if [[ -n "$test_user" ]]; then
    stop_test_user_processes || { cleanup_failed=1; return 1; }
    passwd_record="$(bounded_timeout 10 getent passwd "$test_user" 2>/dev/null)" || rc=$?
    if (( rc == 0 )); then
      IFS=: read -r record_name _ record_uid record_gid _ record_home record_shell <<< "$passwd_record"
      if [[ "$record_name" != "$test_user" || -z "$test_uid"
            || "$record_uid" != "$test_uid" || "$record_gid" != "$test_gid"
            || "$record_home" != "$work_dir/home" || "$record_shell" != /usr/sbin/nologin ]]; then
        cleanup_failed=1
      else
        if (( subid_configured == 1 )); then
          if sudo_bounded usermod --del-subuids "$subid_range" \
              --del-subgids "$subid_range" "$test_user" >/dev/null 2>&1 \
              && verify_subid_absent; then
            subid_configured=0
          else
            cleanup_failed=1
          fi
        fi
        if (( subid_configured == 0 )); then
          sudo_bounded userdel "$test_user" >/dev/null 2>&1 || cleanup_failed=1
        else
          identity_absent=0
        fi
      fi
    elif (( rc != 2 )); then
      cleanup_failed=1
    fi
    rc=0
    if bounded_timeout 10 getent passwd "$test_user" >/dev/null 2>&1; then
      cleanup_failed=1
      identity_absent=0
    else
      rc=$?
      if (( rc != 2 )); then
        cleanup_failed=1
        identity_absent=0
      fi
    fi
    rc=0
    group_record="$(bounded_timeout 10 getent group "$test_user" 2>/dev/null)" || rc=$?
    if (( rc == 0 )); then
      IFS=: read -r group_name _ current_gid group_members <<< "$group_record"
      if [[ "$group_name" != "$test_user" || -z "$test_gid"
            || "$current_gid" != "$test_gid" || -n "$group_members" ]]; then
        cleanup_failed=1
      else
        sudo_bounded groupdel "$test_user" >/dev/null 2>&1 || cleanup_failed=1
      fi
    elif (( rc != 2 )); then
      cleanup_failed=1
    fi
    rc=0
    if bounded_timeout 10 getent group "$test_user" >/dev/null 2>&1; then
      cleanup_failed=1
      identity_absent=0
    else
      rc=$?
      if (( rc != 2 )); then
        cleanup_failed=1
        identity_absent=0
      fi
    fi
  fi
  if [[ "$identity_absent" == 1 ]]; then
    test_user=''
    test_uid=''
    test_gid=''
  fi
  if [[ -n "$work_dir" ]]; then
    if (( workspace_cleaned == 1 )); then
      if [[ -e "$work_dir" || -L "$work_dir" ]]; then
        cleanup_failed=1
      fi
    elif [[ "$identity_absent" == 1 ]] && stop_test_user_processes; then
      if cleanup_workspace "$work_dir" "$workspace_nonce" "$RUNNER_UID" 1; then
        workspace_cleaned=1
      else
        cleanup_failed=1
      fi
    else
      cleanup_failed=1
    fi
  fi
  (( cleanup_failed == 0 )) || return 1
  identity_cleaned=1
}

cleanup() {
  local original_rc=$? teardown_ready=0
  trap - EXIT INT TERM
  set +e
  if (( destructive_teardown_blocked == 1 )); then
    # R92T-FRESH-01: an unowned, foreign, or unverifiable object exists.
    # Only proven-owned resources are cleaned: receipt-held containers
    # (each re-verified by canonical ID immediately before removal), this
    # run's nonce-named firewall chains, and this run's nonce-named
    # database and role. The runner cluster keeps its current state: a
    # cluster-wide stop would act on every database and client that
    # shares it, `cluster_started` proves no exclusive ownership of those,
    # and the stop helper refuses the request under this block as well.
    # The test identity and subids, the private Podman store
    # (graphroot/runroot), the staged rootfs trees, the exec tmpfs mount,
    # and the workspace are preserved for investigation: no cluster-wide
    # stop, UID-wide process kill, user/group/subuid deletion, recursive
    # store or workdir removal, or tmpfs unmount runs while this flag is
    # set, and no report artifact is published. The run always fails with
    # a nonzero exit.
    cleanup_all_containers || cleanup_failed=1
    if remove_firewall_family ip6tables "$firewall6_created"; then
      firewall6_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family iptables "$firewall4_created"; then
      firewall4_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family ip6tables "$firewall_fetch6_created" "$firewall_fetch_chain"; then
      firewall_fetch6_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family iptables "$firewall_fetch4_created" "$firewall_fetch_chain"; then
      firewall_fetch4_created=0
    else cleanup_failed=1; fi
    # The nonce-named role/database and the payload-side passfile are
    # provably this run's and independently removable; neither operation
    # touches or disrupts the unowned object. The cluster stop is
    # deliberately absent here (see above); only the guarded common tail
    # below may attempt it, and never under this block.
    cleanup_database_and_role
    cleanup_failed=1
  elif cleanup_all_containers && stop_test_user_processes; then
    teardown_ready=1
    if remove_firewall_family ip6tables "$firewall6_created"; then
      firewall6_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family iptables "$firewall4_created"; then
      firewall4_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family ip6tables "$firewall_fetch6_created" "$firewall_fetch_chain"; then
      firewall_fetch6_created=0
    else cleanup_failed=1; fi
    if remove_firewall_family iptables "$firewall_fetch4_created" "$firewall_fetch_chain"; then
      firewall_fetch4_created=0
    else cleanup_failed=1; fi
  else
    cleanup_failed=1
  fi
  cleanup_database_and_role
  # R92T-FRESH-01: the cluster stop runs only when no latch is set —
  # including one raised during cleanup_all_containers in either branch
  # above — so a cluster-wide stop stays unreachable in every blocked
  # path; the helper's own guard is the second, call-site-independent
  # refusal.
  if (( destructive_teardown_blocked == 0 && unowned_or_unknown_resource == 0 )); then
    cleanup_cluster
  fi
  if (( teardown_ready == 1 )) && cleanup_exec_files; then
    cleanup_identity_and_files || cleanup_failed=1
  else
    cleanup_failed=1
  fi
  if (( cleanup_failed != 0 || original_rc != 0 )); then
    if (( artifact_created == 1 )); then
      bounded_timeout 15 rm -f -- "$REPORT_PATH" || true
      if [[ -e "$REPORT_PATH" || -L "$REPORT_PATH" ]]; then
        cleanup_failed=1
      fi
    fi
    original_rc=1
  fi
  if [[ -n "$password" ]]; then
    password=''
  fi
  exit "$original_rc"
}

verify_test_user_has_no_sudo_authorization() {
  local output='' rc=0
  output="$(bounded_timeout 15 env -i PATH=/usr/bin:/bin LC_ALL=C \
    "$SUDO_BIN" -n -l -U "$test_user" 2>&1)" || rc=$?
  if (( rc != 1 )) || [[ "$output" != "User $test_user is not allowed to run sudo on "* ]]; then
    output=''
    return 1
  fi
  output=''
}

find_free_subid_range() {
  /usr/bin/python3 - <<'PY'
import pathlib

count = 65536
ranges = []
for filename in ("/etc/subuid", "/etc/subgid"):
    for line in pathlib.Path(filename).read_text(encoding="ascii").splitlines():
        fields = line.split(":")
        if len(fields) != 3 or not fields[1].isdecimal() or not fields[2].isdecimal():
            raise SystemExit(1)
        start, length = int(fields[1]), int(fields[2])
        if length <= 0 or start + length > 2**32:
            raise SystemExit(1)
        ranges.append((start, start + length - 1))
candidate = 100000
for start, end in sorted(ranges):
    candidate = ((candidate + count - 1) // count) * count
    if candidate + count - 1 < start:
        break
    if candidate <= end:
        candidate = end + 1
candidate = ((candidate + count - 1) // count) * count
print(f"{candidate}-{candidate + count - 1}")
PY
}

verify_subid_assignment() {
  /usr/bin/python3 - "$test_user" "$subid_range" <<'PY'
import pathlib
import sys

name, requested = sys.argv[1:]
start_text, end_text = requested.split("-", 1)
if not start_text.isdecimal() or not end_text.isdecimal():
    raise SystemExit(1)
if int(end_text) - int(start_text) + 1 != 65536:
    raise SystemExit(1)
matches = []
for filename in ("/etc/subuid", "/etc/subgid"):
    selected = []
    for line in pathlib.Path(filename).read_text(encoding="ascii").splitlines():
        fields = line.split(":")
        if len(fields) == 3 and fields[0] == name:
            selected.append(f"{fields[1]}-{int(fields[1]) + int(fields[2]) - 1}")
    if selected != [requested]:
        raise SystemExit(1)
    matches.append(selected)
raise SystemExit(0 if len(matches) == 2 else 1)
PY
}

verify_subid_absent() {
  /usr/bin/python3 - "$test_user" <<'PY'
import pathlib
import sys

name = sys.argv[1]
for filename in ("/etc/subuid", "/etc/subgid"):
    if any(line.split(":", 1)[0] == name
           for line in pathlib.Path(filename).read_text(encoding="ascii").splitlines()):
        raise SystemExit(1)
PY
}

container_lifecycle_self_test() {
  # SEC-01 / R92T-INDEPENDENT-01 behavioral check with a mocked Podman
  # client: all three `container exists` outcomes flow through reserve,
  # ownership-receipt claims and validation, failed-create reconciliation,
  # receipt-only removal by canonical ID, repeated cleanup, and the
  # mount-teardown gate. Nothing here touches Podman, sudo, mounts, or
  # /dev/shm beyond a private temporary directory.
  local fixture='' probe='statekit-pg-selftest-probe'
  local probe_id='' foreign_id='' owned_digest='' foreign_digest=''
  local reconcile_status=0
  local partial_class='' owned_class='' absent_class=''
  local dig_contract_only=0
  local -a findmnt_records=() rm_log=()
  fixture="$(bounded_timeout 10 mktemp -d "${TMPDIR:-/tmp}/statekit-container-self-test.XXXXXXXX")" || \
    fixed_error 'container-test-fixture-failed'
  container_self_test_bounded() {
    /usr/bin/timeout --signal=TERM --kill-after=5s "$@"
  }
  container_self_test_state() {
    local value=''
    if read -r value < "$1" 2>/dev/null; then
      printf '%s\n' "$value"
    else
      printf 'unknown\n'
    fi
  }
  podman_as_test_user() {
    case "$1 $2" in
      'container exists')
        case "$(container_self_test_state "$fixture/state-$3")" in
          present) return 0 ;;
          absent) return 1 ;;
          *) return 125 ;;
        esac
        ;;
      'rm --force')
        [[ "$(container_self_test_state "$fixture/rm-rc")" == fail ]] && return 1
        local held_id='' held_name=''
        if IFS='|' read -r held_id held_name _ _ _ < "$fixture/identity-$3" 2>/dev/null; then
          printf 'absent\n' > "$fixture/state-$held_id"
          printf 'absent\n' > "$fixture/state-$held_name"
        fi
        printf 'absent\n' > "$fixture/state-$3"
        printf '%s\n' "$3" >> "$fixture/rm-calls"
        return 0
        ;;
      'inspect --format')
        local line=''
        if [[ "$3" == '{{index .Config.Labels "io.statekit.gate"}}' ]]; then
          read -r line < "$fixture/gate" || return 1
          printf '%s\n' "$line"
          return 0
        fi
        [[ "$3" == "$CONTAINER_OWNERSHIP_FORMAT" ]] || return 125
        read -r line < "$fixture/identity-$4" || return 1
        printf '%s\n' "$line"
        return 0
        ;;
      'ps --all')
        case "$(container_self_test_state "$fixture/ps-state")" in
          error) return 125 ;;
          listed) printf '%s\n' "$(printf '%064d' 6)" ;;
        esac
        return 0
        ;;
    esac
    return 125
  }
  container_self_test_seed() {
    # $1 canonical id, $2 name, $3 nonce, $4 phase, $5 digest: one present
    # container visible under both its ID and its name.
    printf 'present\n' > "$fixture/state-$1"
    printf 'present\n' > "$fixture/state-$2"
    printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" > "$fixture/identity-$1"
    printf '%s|%s|%s|%s|%s\n' "$1" "$2" "$3" "$4" "$5" > "$fixture/identity-$2"
  }
  container_self_test_rm_log() {
    rm_log=()
    [[ ! -e "$fixture/rm-calls" ]] || mapfile -t rm_log < "$fixture/rm-calls"
  }

  printf 'present\n' > "$fixture/state-$probe"
  [[ "$(container_state "$probe")" == present ]] || \
    fixed_error 'container-test-present-state-failed'
  printf 'absent\n' > "$fixture/state-$probe"
  [[ "$(container_state "$probe")" == absent ]] || \
    fixed_error 'container-test-absent-state-failed'
  rm -f "$fixture/state-$probe"
  [[ "$(container_state "$probe")" == unknown ]] || \
    fixed_error 'container-test-unknown-state-failed'

  # Reserve: only a proven-absent name may proceed to create. A present or
  # unknown candidate name latches the destructive-teardown block.
  printf 'present\n' > "$fixture/state-$probe"
  container_must_be_absent "$probe" && \
    fixed_error 'container-test-reserve-accepted-present'
  [[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || \
    fixed_error 'container-test-present-reserve-not-marked'
  rm -f "$fixture/state-$probe"
  container_must_be_absent "$probe" && \
    fixed_error 'container-test-reserve-accepted-unknown'
  printf 'absent\n' > "$fixture/state-$probe"
  container_must_be_absent "$probe" || \
    fixed_error 'container-test-reserve-rejected-absent'

  # R92T-FRESH-01 store preflight: the private run-scoped store must be
  # provably empty before the first create. A listing or an operational
  # error is foreign, is preserved, and latches the block; the latch is
  # monotonic, so a later clean observation never clears it.
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0
  verify_container_store_empty || \
    fixed_error 'container-test-store-empty-failed'
  [[ "$unowned_or_unknown_resource" == 0 ]] || \
    fixed_error 'container-test-empty-store-marked'
  printf 'listed\n' > "$fixture/ps-state"
  verify_container_store_empty && \
    fixed_error 'container-test-store-accepted-listing'
  [[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || \
    fixed_error 'container-test-store-listing-not-marked'
  printf 'error\n' > "$fixture/ps-state"
  verify_container_store_empty && \
    fixed_error 'container-test-store-accepted-error'
  [[ "$unowned_or_unknown_resource" == 1 ]] || \
    fixed_error 'container-test-store-error-not-marked'
  rm -f "$fixture/ps-state"
  # Monotonic latch: a later clean store observation succeeds on its own
  # merits but must never clear the block.
  verify_container_store_empty || \
    fixed_error 'container-test-store-recheck-failed'
  [[ "$unowned_or_unknown_resource" == 1 && "$destructive_teardown_blocked" == 1 ]] || \
    fixed_error 'container-test-store-mark-cleared'
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0

  # Receipt claims require a canonical ID, this run's nonce, and at most one
  # record per ID, name, and phase; cross-run and malformed claims fail.
  run_nonce='0123456789abcdef0123'
  probe_id="$(printf '%064d' 1)"
  foreign_id="$(printf '%064d' 2)"
  owned_digest="$(printf '%064d' 3)"
  foreign_digest="$(printf '%064d' 4)"
  container_receipt=()
  container_receipt_claim "$probe_id" "$probe" mock "$owned_digest" "$run_nonce" \
    || fixed_error 'container-test-claim-failed'
  container_receipt_claim "$probe_id" other-name live "$owned_digest" "$run_nonce" \
    && fixed_error 'container-test-duplicate-id-accepted'
  container_receipt_claim "$(printf '%064d' 9)" "$probe" live "$owned_digest" "$run_nonce" \
    && fixed_error 'container-test-duplicate-name-accepted'
  container_receipt_claim "$(printf '%064d' 8)" other-name mock "$owned_digest" "$run_nonce" \
    && fixed_error 'container-test-duplicate-phase-accepted'
  container_receipt_claim "$(printf '%064d' 7)" other-name live "$owned_digest" 'ffffffffffffffffffff' \
    && fixed_error 'container-test-cross-nonce-accepted'
  container_receipt_claim short-id other-name live "$owned_digest" "$run_nonce" \
    && fixed_error 'container-test-noncanonical-id-accepted'
  # A failed claim (missing/mismatched receipt) latches the block.
  [[ "$unowned_or_unknown_resource" == 1 ]] || \
    fixed_error 'container-test-claim-failure-not-marked'
  container_receipt_release mock
  (( ${#container_receipt[@]} == 0 )) || \
    fixed_error 'container-test-release-failed'
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0

  # A container claimed after a successful create is removed by canonical ID
  # even when a later stage failed; absence is proven and repeated cleanup
  # and verification stay idempotent. A fully owned flow never latches the
  # destructive-teardown block.
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" mock "$owned_digest"
  container_receipt_claim "$probe_id" "$probe" mock "$owned_digest" "$run_nonce" \
    || fixed_error 'container-test-claim-failed'
  containers_cleaned=0
  cleanup_all_containers || fixed_error 'container-test-owned-cleanup-failed'
  [[ "$unowned_or_unknown_resource" == 0 && "$destructive_teardown_blocked" == 0 ]] || \
    fixed_error 'container-test-owned-flow-marked'
  [[ "$(container_self_test_state "$fixture/state-$probe_id")" == absent ]] || \
    fixed_error 'container-test-owned-cleanup-not-proven'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 1 )) || fixed_error 'container-test-removal-count'
  [[ "${rm_log[0]}" == "$probe_id" ]] || \
    fixed_error 'container-test-removal-not-by-canonical-id'
  cleanup_all_containers || fixed_error 'container-test-repeated-cleanup-failed'
  containers_cleaned=0
  verify_containers_absent || \
    fixed_error 'container-test-absent-verification-failed'
  containers_cleaned=1
  cleanup_phase_container mock || fixed_error 'container-test-phase-cleanup-failed'
  (( ${#container_receipt[@]} == 0 )) || \
    fixed_error 'container-test-phase-release-failed'
  cleanup_phase_container mock && \
    fixed_error 'container-test-phase-cleanup-accepted-unclaimed'

  # A pre-existing object sharing the candidate name is foreign: reserve
  # fails closed, latches the block, and EXIT-style cleanup leaves it
  # untouched while this run's teardown is not blocked.
  container_receipt=()
  containers_cleaned=0
  rm -f "$fixture/rm-calls"
  container_self_test_seed "$foreign_id" "$probe" 'ffffffffffffffffffff' live "$foreign_digest"
  container_must_be_absent "$probe" && \
    fixed_error 'container-test-reserve-accepted-preexisting'
  [[ "$unowned_or_unknown_resource" == 1 ]] || \
    fixed_error 'container-test-preexisting-not-marked'
  verify_containers_absent || \
    fixed_error 'container-test-preexisting-blocked-teardown'
  cleanup_all_containers || fixed_error 'container-test-empty-receipt-cleanup-failed'
  [[ "$(container_self_test_state "$fixture/state-$foreign_id")" == present ]] || \
    fixed_error 'container-test-preexisting-object-removed'
  [[ "$(container_self_test_state "$fixture/state-$probe")" == present ]] || \
    fixed_error 'container-test-preexisting-object-removed'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 0 )) || fixed_error 'container-test-preexisting-object-rm-issued'
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0

  # A same-name object whose existence is unknown is preserved as well.
  rm -f "$fixture/state-$probe" "$fixture/state-$foreign_id"
  container_must_be_absent "$probe" && \
    fixed_error 'container-test-reserve-accepted-unknown-name'
  container_receipt=()
  containers_cleaned=0
  cleanup_all_containers || fixed_error 'container-test-unknown-foreign-cleanup-failed'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 0 )) || fixed_error 'container-test-unknown-foreign-rm-issued'

  # Removal failures fail closed with the object preserved: rm failure,
  # unknown existence of the owned container, and a foreign identity.
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" build "$owned_digest"
  container_receipt=()
  containers_cleaned=0
  container_receipt_claim "$probe_id" "$probe" build "$owned_digest" "$run_nonce" \
    || fixed_error 'container-test-claim-failed'
  printf 'fail\n' > "$fixture/rm-rc"
  cleanup_all_containers && fixed_error 'container-test-cleanup-accepted-rm-failure'
  [[ "$(container_self_test_state "$fixture/state-$probe_id")" == present ]] || \
    fixed_error 'container-test-rm-failure-removed-object'
  rm -f "$fixture/rm-rc"
  containers_cleaned=0
  rm -f "$fixture/state-$probe_id" "$fixture/state-$probe"
  cleanup_all_containers && fixed_error 'container-test-cleanup-accepted-unknown-owned'
  [[ "$unowned_or_unknown_resource" == 1 ]] || \
    fixed_error 'container-test-unknown-owned-not-marked'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 0 )) || fixed_error 'container-test-unknown-owned-rm-issued'
  container_receipt_release build
  containers_cleaned=0
  rm -f "$fixture/rm-calls"
  container_self_test_seed "$probe_id" "$probe" 'ffffffffffffffffffff' mock "$owned_digest"
  container_receipt=()
  container_receipt_claim "$probe_id" "$probe" mock "$owned_digest" "$run_nonce" \
    || fixed_error 'container-test-claim-failed'
  cleanup_all_containers && fixed_error 'container-test-cleanup-accepted-foreign-identity'
  [[ "$unowned_or_unknown_resource" == 1 ]] || \
    fixed_error 'container-test-foreign-identity-not-marked'
  [[ "$(container_self_test_state "$fixture/state-$probe_id")" == present ]] || \
    fixed_error 'container-test-foreign-identity-removed'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 0 )) || fixed_error 'container-test-foreign-identity-rm-issued'
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0

  # Reconcile after a failed create: a fully verified partial object is
  # claimed and then cleaned by canonical ID.
  rm -f "$fixture/state-$probe_id" "$fixture/state-$probe" "$fixture/rm-calls"
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" fetch "$owned_digest"
  containers_cleaned=0
  container_receipt=()
  reconcile_partial_create "$probe" fetch "$owned_digest" \
    || fixed_error 'container-test-reconcile-rejected-owned'
  [[ "${container_receipt[0]}" == "$probe_id|$probe|fetch|$owned_digest|$run_nonce" ]] || \
    fixed_error 'container-test-reconcile-claim-malformed'
  cleanup_all_containers || fixed_error 'container-test-reconciled-cleanup-failed'
  [[ "$(container_self_test_state "$fixture/state-$probe_id")" == absent ]] || \
    fixed_error 'container-test-reconciled-cleanup-not-proven'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 1 )) || fixed_error 'container-test-reconciled-removal-count'
  [[ "${rm_log[0]}" == "$probe_id" ]] || \
    fixed_error 'container-test-reconciled-removal-not-by-canonical-id'
  container_receipt=()
  rm -f "$fixture/rm-calls"

  # Ambiguous partial creates are preserved and reported as class 2: a
  # digest mismatch, a foreign nonce, an inspect failure, an unknown state,
  # a non-canonical ID, and a wrong name. A proven-absent name is class 1.
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" fetch "$foreign_digest"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 2 ]] || \
    fixed_error 'container-test-reconcile-accepted-digest-mismatch'
  container_self_test_seed "$probe_id" "$probe" 'ffffffffffffffffffff' fetch "$owned_digest"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 2 ]] || \
    fixed_error 'container-test-reconcile-accepted-foreign-nonce'
  rm -f "$fixture/identity-$probe" "$fixture/identity-$probe_id"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 2 ]] || \
    fixed_error 'container-test-reconcile-accepted-inspect-failure'
  printf 'absent\n' > "$fixture/state-$probe"
  printf 'absent\n' > "$fixture/state-$probe_id"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 1 ]] || \
    fixed_error 'container-test-reconcile-rejected-absent-name'
  printf 'present\n' > "$fixture/state-$probe"
  printf 'shortid|%s|%s|fetch|%s\n' "$probe" "$run_nonce" "$owned_digest" > "$fixture/identity-$probe"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 2 ]] || \
    fixed_error 'container-test-reconcile-accepted-short-id'
  printf '%s|other-name|%s|fetch|%s\n' "$probe_id" "$run_nonce" "$owned_digest" > "$fixture/identity-$probe"
  reconcile_partial_create "$probe" fetch "$owned_digest" || reconcile_status=$?
  [[ "$reconcile_status" == 2 ]] || \
    fixed_error 'container-test-reconcile-accepted-wrong-name'
  (( ${#container_receipt[@]} == 0 )) || \
    fixed_error 'container-test-reconcile-claimed-ambiguous-object'
  container_self_test_rm_log
  (( ${#rm_log[@]} == 0 )) || fixed_error 'container-test-reconcile-removed-ambiguous-object'

  # create_failed_reconcile mapping (checked in a subshell because the
  # unowned class exits): a foreign/ambiguous partial object keeps the
  # distinct fixed unowned class, while a fully verified partial object or
  # a proven-absent name keeps the phase's own class.
  container_receipt=()
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0
  container_self_test_seed "$probe_id" "$probe" 'ffffffffffffffffffff' fetch "$owned_digest"
  partial_class=''
  partial_class="$(create_failed_reconcile "$probe" fetch "$owned_digest" \
    'fetch-container-create-failed' 2>&1)" \
    && fixed_error 'container-test-partial-reconcile-succeeded'
  [[ "$partial_class" == 'podman-create-partial-object-unowned' ]] || \
    fixed_error 'container-test-partial-class-invalid'
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" fetch "$owned_digest"
  owned_class=''
  owned_class="$(create_failed_reconcile "$probe" fetch "$owned_digest" \
    'fetch-container-create-failed' 2>&1)" \
    && fixed_error 'container-test-owned-reconcile-succeeded'
  [[ "$owned_class" == 'fetch-container-create-failed' ]] || \
    fixed_error 'container-test-owned-class-invalid'
  printf 'absent\n' > "$fixture/state-$probe"
  printf 'absent\n' > "$fixture/state-$probe_id"
  absent_class=''
  absent_class="$(create_failed_reconcile "$probe" fetch "$owned_digest" \
    'fetch-container-create-failed' 2>&1)" \
    && fixed_error 'container-test-absent-reconcile-succeeded'
  [[ "$absent_class" == 'fetch-container-create-failed' ]] || \
    fixed_error 'container-test-absent-class-invalid'
  container_receipt=()
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0

  # Mount teardown: no findmnt/unmount while a receipt-held container is
  # not proven absent; a foreign same-name object never blocks teardown of
  # this run's own resources. (The counter is a file because the inspected
  # call runs in a $( ) subshell whose variable updates do not propagate.)
  workspace_nonce="$(python3 -c 'import secrets; print(secrets.token_hex(10))')" || \
    fixed_error 'container-test-nonce-failed'
  exec_mountpoint="/dev/shm/statekit-exec-$workspace_nonce"
  rootfs_dir='' fetch_rootfs_dir='' exec_artifacts_dir=''
  exec_mountpoint_created=0 exec_mount_mounted=0
  sudo_bounded() { return 1; }
  run_as_test_user() { return 1; }
  bounded_timeout() {
    local seconds="$1"
    shift
    if [[ "$1" == "$FINDMNT_BIN" ]]; then
      printf 'findmnt\n' >> "$fixture/findmnt-calls"
      return 1
    fi
    container_self_test_bounded "$seconds" "$@"
  }
  containers_cleaned=0
  container_receipt=()
  printf 'present\n' > "$fixture/state-$probe"
  remove_exec_mount || fixed_error 'container-test-teardown-rejected-empty-receipt'
  findmnt_records=()
  [[ ! -e "$fixture/findmnt-calls" ]] || \
    mapfile -t findmnt_records < "$fixture/findmnt-calls"
  (( ${#findmnt_records[@]} == 1 )) || \
    fixed_error 'container-test-teardown-findmnt-empty-receipt-count'
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" live "$owned_digest"
  container_receipt=()
  container_receipt_claim "$probe_id" "$probe" live "$owned_digest" "$run_nonce" \
    || fixed_error 'container-test-claim-failed'
  remove_exec_mount && fixed_error 'container-test-teardown-accepted-present'
  rm -f "$fixture/state-$probe_id"
  remove_exec_mount && fixed_error 'container-test-teardown-accepted-unknown'
  printf 'absent\n' > "$fixture/state-$probe_id"
  remove_exec_mount || fixed_error 'container-test-teardown-rejected-absent'
  findmnt_records=()
  [[ ! -e "$fixture/findmnt-calls" ]] || \
    mapfile -t findmnt_records < "$fixture/findmnt-calls"
  (( ${#findmnt_records[@]} == 2 )) || fixed_error 'container-test-teardown-findmnt-count'

  # R92T-FRESH-01 residual: while the destructive-teardown block is
  # latched, a cluster-wide stop is unreachable. The helper is a no-op
  # that reports only the fixed value-free skip class and never reaches
  # the (stubbed) privilege boundary; unlatched, the ordinary stop path
  # is still attempted and here fails closed through that stub.
  cluster_started=1
  mark_unowned_resource
  cluster_skip_class=''
  cluster_skip_class="$(cleanup_cluster 2>&1)" || \
    fixed_error 'container-test-cluster-skip-failed'
  [[ "$cluster_skip_class" == 'cluster-stop-skipped-unowned-resource' ]] || \
    fixed_error 'container-test-cluster-skip-class-invalid'
  [[ "$cluster_started" == 1 ]] || \
    fixed_error 'container-test-cluster-skip-reset-state'
  unowned_or_unknown_resource=0
  destructive_teardown_blocked=0
  cleanup_cluster && fixed_error 'container-test-cluster-stop-not-attempted'
  cluster_started=0

  # Exercise the production dig-only claim/reconciliation guards, not a
  # parallel ownership implementation. Same labels on failed create confer
  # no ownership; even successful receipts require the exact gate label.
  dig_contract_only=1
  container_receipt=()
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" build "$owned_digest"
  printf 'foreign\n' > "$fixture/gate"
  if container_receipt_claim "$probe_id" "$probe" build "$owned_digest" "$run_nonce"; then
    fixed_error 'dig-test-foreign-gate-claimed'
  fi
  (( ${#container_receipt[@]} == 0 )) || fixed_error 'dig-test-unowned-receipt'
  printf 'dig-contract\n' > "$fixture/gate"
  container_receipt_claim "$probe_id" "$probe" build "$owned_digest" "$run_nonce" || fixed_error 'dig-test-receipt-not-claimed'
  cleanup_owned_container "$probe_id" "$probe" build "$owned_digest" "$run_nonce" || fixed_error 'dig-test-owned-cleanup-failed'
  container_receipt=()
  container_self_test_seed "$probe_id" "$probe" "$run_nonce" fetch "$owned_digest"
  if partial_class="$(create_failed_reconcile "$probe" fetch "$owned_digest" 'fetch-failed' 2>&1)"; then
    fixed_error 'dig-test-partial-create-accepted'
  fi
  [[ "$partial_class" == podman-create-partial-object-unowned \
     && "$(container_state "$probe_id")" == present ]] || fixed_error 'dig-test-partial-create-not-preserved'
  dig_contract_only=0
  container_self_test_bounded 15 rm -rf --one-file-system -- "$fixture" || \
    fixed_error 'container-test-cleanup-failed'
  [[ ! -e "$fixture" && ! -L "$fixture" ]] || \
    fixed_error 'container-test-fixture-residual'
}

case "$self_test_mode" in
  workspace)
    workspace_self_test
    exit 0
    ;;
  container-lifecycle)
    container_lifecycle_self_test
    exit 0
    ;;
esac
[[ "$#" == 0 || ( "$#" == 1 && "$dig_contract_only" == 1 ) ]] || fixed_error 'invalid-controller-arguments'

GO_BIN="$(command -v go)" || fixed_error 'go-toolchain-unavailable'
GO_BIN_DIR="$(dirname "$GO_BIN")"
PODMAN_BIN="$(command -v podman)" || fixed_error 'rootless-podman-unavailable'
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
preflight_exec_mount_plan || fixed_error 'exec-tmpfs-preflight-failed'
if (( dig_contract_only == 1 )); then
  PG_BINDIR=/usr/bin
  [[ "$GO_BIN" == /usr/local/go/bin/go || "$GO_BIN" == /opt/hostedtoolcache/go/1.26.8/x64/bin/go ]] || fixed_error 'dig-runner-go-path-unverified'
  [[ "$(env -i PATH=/usr/bin:/bin GOTOOLCHAIN=local GOENV=off "$GO_BIN" version)" == 'go version go1.26.8 linux/amd64' ]] || fixed_error 'dig-runner-go-version-mismatch'
else
  PG_BINDIR="$(pg_config --bindir)" || fixed_error 'postgres-client-tools-unavailable'
  PSQL_BIN="$PG_BINDIR/psql"
  [[ -x "$PSQL_BIN" && ! -L "$PSQL_BIN" ]] || fixed_error 'postgres-client-unavailable'
fi
[[ "$PODMAN_BIN" == /usr/bin/podman ]] || fixed_error 'rootless-podman-path-invalid'

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if (( dig_contract_only == 0 )); then
verify_postgres_admin_preflight || fixed_error 'postgres-admin-preflight-failed'

# Only after preflight: reject unsafe artifact path components, then clear a
# stale report so this run can never publish old evidence.
[[ ! -L "$ROOT/artifacts" && ! -L "$REPORT_DIR" ]] || fixed_error 'unsafe-report-path'
mkdir -p "$REPORT_DIR"
[[ ! -L "$REPORT_DIR" && -d "$REPORT_DIR" ]] || fixed_error 'unsafe-report-path'
bounded_timeout 15 rm -f -- "$REPORT_PATH"
[[ ! -e "$REPORT_PATH" && ! -L "$REPORT_PATH" ]] || fixed_error 'stale-report-rejected'
fi

nonce="$run_nonce"
[[ "$nonce" =~ ^[0-9a-f]{20}$ ]] || fixed_error 'random-resource-name-failed'
test_user="statekit-pg-${nonce:0:12}"
db_name="statekit_pg_$nonce"
db_role="statekit_user_$nonce"
firewall_chain="SKPG${nonce}"
firewall_fetch_chain="SKPF${nonce}"
work_dir="$(bounded_timeout 10 mktemp -d "/dev/shm/statekit-pg-${nonce}.XXXXXXXX")" || \
  fixed_error 'workspace-creation-failed'
workspace_nonce="$nonce"
workspace_identity_matches "$work_dir" "$workspace_nonce" "$RUNNER_UID" || \
  fixed_error 'unsafe-workspace'

for account_type in passwd group; do
  if bounded_timeout 10 getent "$account_type" "$test_user" >/dev/null 2>&1; then
    fixed_error 'test-user-name-collision'
  else
    account_rc=$?
    [[ "$account_rc" == 2 ]] || fixed_error 'test-user-account-preflight-failed'
  fi
done
sudo_bounded useradd --system --user-group --no-create-home \
  --home-dir "$work_dir/home" --shell /usr/sbin/nologin "$test_user" >/dev/null 2>&1 || \
  fixed_error 'test-user-creation-failed'
test_uid="$(bounded_timeout 10 id -u "$test_user")" || fixed_error 'test-user-not-unprivileged'
test_gid="$(bounded_timeout 10 id -g "$test_user")" || fixed_error 'test-user-not-unprivileged'
[[ "$test_uid" =~ ^[0-9]+$ && "$test_uid" != 0 && "$test_gid" =~ ^[0-9]+$ ]] || \
  fixed_error 'test-user-not-unprivileged'
verify_test_user_has_no_sudo_authorization || fixed_error 'test-user-sudo-policy-failed'
verify_rootless_helpers || fixed_error 'rootless-helper-policy-failed'
create_exec_mount || fixed_error 'exec-tmpfs-mount-failed'
exec_artifacts_dir="$exec_mountpoint/artifacts"
sudo_bounded install -d -o "$test_uid" -g "$test_gid" -m 0700 \
  "$exec_artifacts_dir" || fixed_error 'exec-artifacts-directory-failed'
verify_exec_mount_identity || fixed_error 'exec-artifacts-directory-failed'
subid_range="$(find_free_subid_range)" || fixed_error 'rootless-subid-range-unavailable'
[[ "$subid_range" =~ ^[0-9]+-[0-9]+$ ]] || fixed_error 'rootless-subid-range-unavailable'
sudo_bounded usermod --add-subuids "$subid_range" --add-subgids "$subid_range" \
  "$test_user" >/dev/null 2>&1 || fixed_error 'rootless-subid-setup-failed'
subid_configured=1
verify_subid_assignment || fixed_error 'rootless-subid-policy-failed'
sudo_bounded chown "$RUNNER_UID:$test_gid" "$work_dir" || fixed_error 'workspace-permissions-failed'
chmod 0750 "$work_dir"
sudo_bounded install -d -o "$test_uid" -g "$test_gid" -m 0700 \
  "$work_dir/run" "$work_dir/run/home" "$work_dir/run/tmp" \
  "$work_dir/run/gocache" "$work_dir/run/gomodcache" \
  "$work_dir/run/live-output" \
  "$work_dir/run/podman-runtime" "$work_dir/run/podman-config" \
  "$work_dir/run/podman-data" "$work_dir/run/podman-cache" \
  "$work_dir/run/podman-root" "$work_dir/run/podman-runroot" || \
  fixed_error 'test-workspace-creation-failed'
run_dir="$work_dir/run"
podman_runtime="$run_dir/podman-runtime"
podman_root="$run_dir/podman-root"
podman_runroot="$run_dir/podman-runroot"
rootfs_dir="$exec_mountpoint/rootfs"
fetch_rootfs_dir="$exec_mountpoint/rootfs-fetch"
test_env_base=(
  "PATH=$PG_BINDIR"
  "HOME=$run_dir/home"
  "TMPDIR=$run_dir/tmp"
  "LC_ALL=C"
  "PYTHONDONTWRITEBYTECODE=1"
)

mkdir "$work_dir/manifests"
sudo_bounded chown "$RUNNER_UID:$test_gid" "$work_dir/manifests"
chmod 0750 "$work_dir/manifests"
install -m 0440 go.mod go.sum "$work_dir/manifests/"
sudo_bounded chown "$RUNNER_UID:$test_gid" "$work_dir/manifests/go.mod" "$work_dir/manifests/go.sum"

# SEC-03: the host never runs `go mod download`. The fixed fetch runs in its
# own manifest-closed rootfs container with the fixed Go binary/argv, the
# read-only go.mod/go.sum pair, a fixed public proxy with no direct fallback,
# the public checksum database, an isolated tmpfs HOME, and exactly one
# writable output: the go-module cache. No checkout source, scripts, hooks,
# credentials, sockets, or other host paths are present, and the effective
# configuration is inspected before start.
GO_ROOT="$(env -i PATH=/usr/bin:/bin HOME=/nonexistent GOTOOLCHAIN=local GOENV=off GOWORK=off "$GO_BIN" env GOROOT)" || fixed_error 'go-root-unavailable'
run_as_test_user "$ROOT" /usr/bin/python3 \
  tests/live/postgres/rootfs.py full --profile fetch \
  --destination "$fetch_rootfs_dir" --uid "$test_uid" --gid "$test_gid" \
  --exec-mount "$exec_mountpoint" \
  --go-root "$GO_ROOT" --bash /usr/bin/bash --sh /usr/bin/sh || \
  fixed_error 'fetch-rootfs-build-failed'
verify_exec_mount_identity || fixed_error 'fetch-rootfs-build-failed'
[[ "$(run_as_test_user "$ROOT" /usr/bin/stat -c '%u:%g:%a' -- "$fetch_rootfs_dir")" \
   == "$test_uid:$test_gid:755" ]] || fixed_error 'fetch-rootfs-build-failed'
fetch_manifest_sha256="$(run_as_test_user "$ROOT" \
  /usr/bin/sha256sum "$fetch_rootfs_dir/etc/statekit-rootfs.manifest")" || \
  fixed_error 'fetch-rootfs-manifest-hash-failed'
fetch_manifest_sha256="${fetch_manifest_sha256%% *}"
[[ "$fetch_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || \
  fixed_error 'fetch-rootfs-manifest-hash-failed'
verify_rootfs_authoritative "$fetch_rootfs_dir" dependency-fetch \
  "$fetch_manifest_sha256" || fixed_error 'fetch-rootfs-verification-failed'

resolve_fetch_endpoints || fixed_error 'fetch-egress-endpoints-unavailable'
# Both families are constrained unconditionally: a family whose endpoint
# resolution came back empty still installs its resolver-only default-drop
# chain instead of leaving that family unfiltered.
install_fetch_firewall_family iptables 127.0.0.53/32 \
  firewall_fetch4_created "${proxy_addresses_v4[@]}" || \
  fixed_error 'ipv4-fetch-egress-setup-failed'
install_fetch_firewall_family ip6tables ::1/128 \
  firewall_fetch6_created "${proxy_addresses_v6[@]}" || \
  fixed_error 'ipv6-fetch-egress-setup-failed'
verify_effective_fetch_firewall_family iptables 127.0.0.53/32 \
  "${proxy_addresses_v4[@]}" || fixed_error 'ipv4-fetch-egress-preflight-failed'
verify_effective_fetch_firewall_family ip6tables ::1/128 \
  "${proxy_addresses_v6[@]}" || fixed_error 'ipv6-fetch-egress-preflight-failed'

verify_rootless_podman || fixed_error 'rootless-podman-preflight-failed'
# R92T-FRESH-01: prove the private run-scoped rootless store is empty
# before the first create; a non-empty or unverifiable store is foreign,
# preserved as-is, and fails the run before any container is created.
verify_container_store_empty || fixed_error 'podman-store-not-empty'
fetch_container="statekit-pg-fetch-$nonce"
container_must_be_absent "$fetch_container" || \
  fixed_error 'podman-container-name-collision'
fetch_env_names=(
  PATH HOME TMPDIR GOCACHE GOMODCACHE GOENV GOTOOLCHAIN GOWORK GOPROXY GOSUMDB
  GOPRIVATE GONOPROXY GONOSUMDB CGO_ENABLED GOFLAGS LC_ALL
  STATEKIT_TEST_UID STATEKIT_TEST_GID STATEKIT_ROOTFS_MANIFEST_SHA256
  STATEKIT_ROOTFS_ROLE
)
fetch_binds=(
  "/deps=$work_dir/manifests:ro"
  "/modules=$run_dir/gomodcache:rw"
)
test_command_timeout=700
verify_rootfs_authoritative "$fetch_rootfs_dir" dependency-fetch \
  "$fetch_manifest_sha256" || fixed_error 'fetch-rootfs-verification-failed'
if ! fetch_container_id="$(podman_as_test_user create --rootfs \
  --name "$fetch_container" --network=host --userns=keep-id \
  --user "$test_uid:$test_gid" --read-only --read-only-tmpfs=false \
  --memory 4g --cpus 2 --pids-limit 256 --shm-size 64m --timeout 600 \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g,mode=1777 \
  --tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt no-new-privileges \
  --ipc=private --pid=private --uts=private --no-hosts --no-hostname \
  --http-proxy=false --unsetenv-all \
  --env PATH=/opt/go/bin:/usr/bin:/bin \
  --env HOME=/tmp --env TMPDIR=/tmp \
  --env GOCACHE=/tmp/gocache --env GOMODCACHE=/modules \
  --env GOENV=off --env GOTOOLCHAIN=local --env GOWORK=off \
  --env GOPROXY=https://proxy.golang.org --env GOSUMDB=sum.golang.org \
  --env GOPRIVATE= --env GONOPROXY= --env GONOSUMDB= \
  --env CGO_ENABLED=0 --env GOFLAGS=-mod=readonly --env LC_ALL=C \
  --env STATEKIT_TEST_UID="$test_uid" --env STATEKIT_TEST_GID="$test_gid" \
  --env STATEKIT_ROOTFS_MANIFEST_SHA256="$fetch_manifest_sha256" \
  --env STATEKIT_ROOTFS_ROLE=fetch \
  --volume "$work_dir/manifests:/deps:ro,nosuid,nodev,noexec,rprivate" \
  --volume "$run_dir/gomodcache:/modules:rw,nosuid,nodev,noexec,rprivate" \
  --workdir /deps \
  --label "io.statekit.rootfs.path=$fetch_rootfs_dir" \
  --label "io.statekit.rootfs.manifest-sha256=$fetch_manifest_sha256" \
  --label "io.statekit.run.nonce=$run_nonce" \
  --label "io.statekit.phase=fetch" \
  --label "io.statekit.gate=$([[ "$dig_contract_only" == 1 ]] && printf dig-contract || printf postgres-live)" \
  "$fetch_rootfs_dir" \
  /usr/bin/statekit-rootfs-preflight /opt/go/bin/go mod download \
  2>/dev/null)"; then
  create_failed_reconcile "$fetch_container" fetch "$fetch_manifest_sha256" \
    'fetch-container-create-failed'
fi
# R92T-INDEPENDENT-01: the canonical ID returned by create plus the
# immutable ownership labels are recorded before any inspect or start.
container_receipt_claim "$fetch_container_id" "$fetch_container" fetch \
  "$fetch_manifest_sha256" "$run_nonce" \
  || fixed_error 'container-ownership-receipt-invalid'
if (( dig_contract_only == 1 )); then fetch_container="$fetch_container_id"; fi
verify_podman_container "$fetch_container" host fetch_env_names fetch_binds \
  "$fetch_rootfs_dir" "$fetch_manifest_sha256" || \
  fixed_error 'fetch-container-policy-failed'
verify_rootfs_authoritative "$fetch_rootfs_dir" dependency-fetch \
  "$fetch_manifest_sha256" || fixed_error 'fetch-rootfs-verification-failed'
# The effective dual-family policy is re-verified immediately before the
# network-enabled fetch starts.
verify_effective_fetch_firewall_family iptables 127.0.0.53/32 \
  "${proxy_addresses_v4[@]}" || fixed_error 'ipv4-fetch-egress-preflight-failed'
verify_effective_fetch_firewall_family ip6tables ::1/128 \
  "${proxy_addresses_v6[@]}" || fixed_error 'ipv6-fetch-egress-preflight-failed'
if ! podman_as_test_user start --attach "$fetch_container" >/dev/null 2>&1; then
  fixed_error 'go-module-fetch-failed'
fi
[[ "$(podman_as_test_user inspect --format '{{.State.Status}}' "$fetch_container")" == exited \
   && "$(podman_as_test_user inspect --format '{{.State.ExitCode}}' "$fetch_container")" == 0 ]] || \
  fixed_error 'go-module-fetch-failed'
cleanup_phase_container fetch || fixed_error 'fetch-container-cleanup-failed'
fetch_container=''
if stop_test_user_processes; then
  remove_firewall_family ip6tables "$firewall_fetch6_created" \
    "$firewall_fetch_chain" || fixed_error 'ipv6-fetch-egress-cleanup-failed'
  firewall_fetch6_created=0
  remove_firewall_family iptables "$firewall_fetch4_created" \
    "$firewall_fetch_chain" || fixed_error 'ipv4-fetch-egress-cleanup-failed'
  firewall_fetch4_created=0
else
  fixed_error 'test-user-process-cleanup-failed'
fi

# Safe dependency acquisition above never touches the checkout. The minimal
# runner rootfs is staged only inside the verified exec tmpfs; project builds,
# Go tests, and the Python orchestration mocks execute in no-network rootfs
# containers, never from the runner checkout.
PYTHON_BIN=/usr/bin/python3
BASH_BIN=/usr/bin/bash
SH_BIN=/usr/bin/sh
rootfs_profile_args=(--psql "$PSQL_BIN")
if (( dig_contract_only == 1 )); then rootfs_profile_args=(--profile dig-contract); fi
run_as_test_user "$ROOT" /usr/bin/python3 \
  tests/live/postgres/rootfs.py full \
  --destination "$rootfs_dir" --uid "$test_uid" --gid "$test_gid" \
  --exec-mount "$exec_mountpoint" \
  --go-root "$GO_ROOT" "${rootfs_profile_args[@]}" --python "$PYTHON_BIN" \
  --bash "$BASH_BIN" --sh "$SH_BIN" || fixed_error 'minimal-rootfs-build-failed'
verify_exec_mount_identity || fixed_error 'exec-tmpfs-identity-lost'
[[ "$(run_as_test_user "$ROOT" /usr/bin/stat -c '%u:%g:%a' -- "$rootfs_dir")" == "$test_uid:$test_gid:755" \
   && "$(run_as_test_user "$ROOT" /usr/bin/stat -c '%u:%g:%a' -- "$rootfs_dir/etc/statekit-rootfs.manifest")" == "$test_uid:$test_gid:644" ]] || \
  fixed_error 'minimal-rootfs-manifest-unavailable'
rootfs_manifest_sha256="$(run_as_test_user "$ROOT" /usr/bin/sha256sum "$rootfs_dir/etc/statekit-rootfs.manifest")" || \
  fixed_error 'minimal-rootfs-manifest-hash-failed'
rootfs_manifest_sha256="${rootfs_manifest_sha256%% *}"
[[ "$rootfs_manifest_sha256" =~ ^[0-9a-f]{64}$ ]] || fixed_error 'minimal-rootfs-manifest-hash-failed'
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
rootfs_library_path="$(run_as_test_user "$ROOT" /usr/bin/python3 - "$rootfs_dir" <<'PY'
import json
from pathlib import Path
import sys

root = Path(sys.argv[1])
manifest_path = root / "etc/statekit-rootfs.manifest"
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
if manifest.get("runtime_profile") not in ("live-executable", "dig-contract"):
    raise SystemExit(1)
directories = manifest.get("library_path")
allowed = ("/lib", "/lib64", "/usr/lib", "/usr/lib64",
           "/usr/local/lib", "/usr/local/lib64", "/usr/lib/postgresql/16")
if not isinstance(directories, list) or not directories or directories != sorted(set(directories)):
    raise SystemExit(1)
for value in directories:
    if (not isinstance(value, str) or not value.startswith("/") or value == "/"
            or ":" in value or ".." in Path(value).parts
            or not any(value == prefix or value.startswith(prefix + "/") for prefix in allowed)):
        raise SystemExit(1)
    staged = root / value.lstrip("/")
    if not staged.is_dir() or staged.is_symlink():
        raise SystemExit(1)
print(":".join(directories))
PY
)" || fixed_error 'rootfs-library-path-invalid'
[[ -n "$rootfs_library_path" ]] || fixed_error 'rootfs-library-path-invalid'

verify_rootless_podman || fixed_error 'rootless-podman-preflight-failed'
build_container="statekit-pg-build-$nonce"
container_must_be_absent "$build_container" || \
  fixed_error 'podman-container-name-collision'
build_env_names=(
  PATH GOROOT HOME TMPDIR GOCACHE GOMODCACHE GOENV GOTOOLCHAIN GOWORK
  GOPROXY GOSUMDB GOPRIVATE GONOPROXY GONOSUMDB CGO_ENABLED GOFLAGS LD_LIBRARY_PATH LC_ALL
  PYTHONDONTWRITEBYTECODE STATEKIT_TEST_UID STATEKIT_TEST_GID
  STATEKIT_ROOTFS_MANIFEST_SHA256 STATEKIT_ROOTFS_ROLE
)
build_binds=(
  "/workspace=$ROOT:ro" "/modules=$run_dir/gomodcache:ro"
  "/out=$exec_artifacts_dir:rw"
)
build_command=(
  /usr/bin/statekit-rootfs-preflight /bin/bash -euo pipefail -c
  'python3 -B /workspace/tests/live/postgres/run.py --assert-container-privileges && go mod verify && go build -trimpath -buildvcs=false -o /out/statekit ./cmd/statekit && go test ./...'
)
build_go_cache=/tmp/gocache
if (( dig_contract_only == 1 )); then
  build_go_cache=/out/gocache
  build_command=(/usr/bin/statekit-rootfs-preflight /bin/bash -euo pipefail -c
    '[[ "$(go version)" == "go version go1.26.8 linux/amd64" ]] && python3 -B -m unittest discover -s tests/live/dig -p test_orchestration.py -v && go mod verify && go test -tags=dns_contract -count=1 ./modules/exec/dig ./internal/cli ./tests/differential ./modules/exec/dnsutil')
fi
test_command_timeout=900
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
if ! build_container_id="$(podman_as_test_user create --rootfs \
  --name "$build_container" --network=none --userns=keep-id \
  --user "$test_uid:$test_gid" --read-only --read-only-tmpfs=false \
  --memory 4g --cpus 2 --pids-limit 256 --shm-size 64m --timeout 900 \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g,mode=1777 \
  --tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt no-new-privileges \
  --ipc=private --pid=private --uts=private --no-hosts --no-hostname \
  --http-proxy=false --unsetenv-all \
  --env PATH=/opt/go/bin:/usr/lib/postgresql/16/bin:/usr/bin:/bin \
  --env "LD_LIBRARY_PATH=$rootfs_library_path" \
  --env GOROOT=/opt/go --env HOME=/tmp --env TMPDIR=/tmp \
  --env "GOCACHE=$build_go_cache" --env GOMODCACHE=/modules \
  --env GOENV=off --env GOTOOLCHAIN=local --env GOWORK=off \
  --env GOPROXY=off --env GOSUMDB=sum.golang.org --env GOPRIVATE= \
  --env GONOPROXY= --env GONOSUMDB= --env CGO_ENABLED=0 \
  --env GOFLAGS=-mod=readonly --env LC_ALL=C --env PYTHONDONTWRITEBYTECODE=1 \
  --env STATEKIT_TEST_UID="$test_uid" --env STATEKIT_TEST_GID="$test_gid" \
  --env STATEKIT_ROOTFS_MANIFEST_SHA256="$rootfs_manifest_sha256" \
  --env STATEKIT_ROOTFS_ROLE=build \
  --volume "$ROOT:/workspace:ro,nosuid,nodev,noexec,rprivate" \
  --volume "$run_dir/gomodcache:/modules:ro,nosuid,nodev,noexec,rprivate" \
  --volume "$exec_artifacts_dir:/out:rw,nosuid,nodev,noexec,rprivate" \
  --workdir /workspace \
  --label "io.statekit.rootfs.path=$rootfs_dir" \
  --label "io.statekit.rootfs.manifest-sha256=$rootfs_manifest_sha256" \
  --label "io.statekit.run.nonce=$run_nonce" \
  --label "io.statekit.phase=build" \
  --label "io.statekit.gate=$([[ "$dig_contract_only" == 1 ]] && printf dig-contract || printf postgres-live)" \
  "$rootfs_dir" "${build_command[@]}" 2>/dev/null)"; then
  create_failed_reconcile "$build_container" build "$rootfs_manifest_sha256" \
    'rootfs-container-create-failed'
fi
container_receipt_claim "$build_container_id" "$build_container" build \
  "$rootfs_manifest_sha256" "$run_nonce" \
  || fixed_error 'container-ownership-receipt-invalid'
if (( dig_contract_only == 1 )); then build_container="$build_container_id"; fi
verify_podman_container "$build_container" none build_env_names build_binds \
  "$rootfs_dir" "$rootfs_manifest_sha256" || \
  fixed_error 'rootfs-container-policy-failed'
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
if ! podman_as_test_user start --attach "$build_container" >/dev/null 2>&1; then
  fixed_error 'isolated-build-or-mock-tests-failed'
fi
[[ "$(podman_as_test_user inspect --format '{{.State.Status}}' "$build_container")" == exited \
   && "$(podman_as_test_user inspect --format '{{.State.ExitCode}}' "$build_container")" == 0 ]] || \
  fixed_error 'isolated-build-or-mock-tests-failed'
if (( dig_contract_only == 1 )); then
  printf '%s\n' 'dig-contract-offline-passed'
  exit 0
fi
statekit_artifact="$exec_artifacts_dir/statekit"
artifact_metadata="$(sudo_bounded stat -c '%u:%g:%a:%h' "$statekit_artifact")" || \
  fixed_error 'production-binary-artifact-unavailable'
[[ "$(sudo_bounded test -f "$statekit_artifact" && printf regular)" == regular \
   && "$(sudo_bounded test -L "$statekit_artifact" && printf symlink || true)" != symlink \
   && "$artifact_metadata" == "$test_uid:$test_gid:755:1" ]] || \
  fixed_error 'production-binary-artifact-unavailable'
artifact_digest="$(sudo_bounded sha256sum -- "$statekit_artifact")" || \
  fixed_error 'production-binary-artifact-unavailable'
artifact_digest="${artifact_digest%% *}"
[[ "$artifact_digest" =~ ^[0-9a-f]{64}$ ]] || \
  fixed_error 'production-binary-artifact-unavailable'
sudo_bounded chmod 0555 "$statekit_artifact" || fixed_error 'production-binary-artifact-mode-failed'
statekit_artifact_digest="$artifact_digest"

mock_container="statekit-pg-mock-$nonce"
container_must_be_absent "$mock_container" || \
  fixed_error 'podman-container-name-collision'
mock_env_names=(
  PATH LD_LIBRARY_PATH HOME TMPDIR LC_ALL PYTHONDONTWRITEBYTECODE
  STATEKIT_TEST_UID STATEKIT_TEST_GID STATEKIT_ROOTFS_MANIFEST_SHA256
  STATEKIT_ROOTFS_ROLE
)
mock_binds=("/workspace=$ROOT:ro")
mock_command=(/usr/bin/statekit-rootfs-preflight /bin/bash -euo pipefail -c \
  'python3 -B /workspace/tests/live/postgres/run.py --assert-container-privileges && python3 -B /workspace/tests/live/postgres/test_orchestration.py')
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
if ! mock_container_id="$(podman_as_test_user create --rootfs \
  --name "$mock_container" --network=none --userns=keep-id \
  --user "$test_uid:$test_gid" --read-only --read-only-tmpfs=false \
  --memory 4g --cpus 2 --pids-limit 256 --shm-size 64m --timeout 900 \
  --tmpfs /tmp:rw,nosuid,nodev,size=2g,mode=1777 \
  --tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt no-new-privileges \
  --ipc=private --pid=private --uts=private --no-hosts --no-hostname \
  --http-proxy=false --unsetenv-all \
  --env PATH=/usr/bin:/bin --env "LD_LIBRARY_PATH=$rootfs_library_path" \
  --env HOME=/tmp --env TMPDIR=/tmp \
  --env LC_ALL=C --env PYTHONDONTWRITEBYTECODE=1 \
  --env STATEKIT_TEST_UID="$test_uid" --env STATEKIT_TEST_GID="$test_gid" \
  --env STATEKIT_ROOTFS_MANIFEST_SHA256="$rootfs_manifest_sha256" \
  --env STATEKIT_ROOTFS_ROLE=mock \
  --volume "$ROOT:/workspace:ro,nosuid,nodev,noexec,rprivate" \
  --workdir /workspace \
  --label "io.statekit.rootfs.path=$rootfs_dir" \
  --label "io.statekit.rootfs.manifest-sha256=$rootfs_manifest_sha256" \
  --label "io.statekit.run.nonce=$run_nonce" \
  --label "io.statekit.phase=mock" \
  "$rootfs_dir" "${mock_command[@]}" 2>/dev/null)"; then
  create_failed_reconcile "$mock_container" mock "$rootfs_manifest_sha256" \
    'mock-container-create-failed'
fi
container_receipt_claim "$mock_container_id" "$mock_container" mock \
  "$rootfs_manifest_sha256" "$run_nonce" \
  || fixed_error 'container-ownership-receipt-invalid'
verify_podman_container "$mock_container" none mock_env_names mock_binds \
  "$rootfs_dir" "$rootfs_manifest_sha256" || \
  fixed_error 'mock-container-policy-failed'
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
if ! podman_as_test_user start --attach "$mock_container" >/dev/null 2>&1; then
  fixed_error 'rootless-python-mocks-failed'
fi
[[ "$(podman_as_test_user inspect --format '{{.State.Status}}' "$mock_container")" == exited \
   && "$(podman_as_test_user inspect --format '{{.State.ExitCode}}' "$mock_container")" == 0 ]] || \
  fixed_error 'rootless-python-mocks-failed'

# Use only the already-installed 16/main cluster. If it was stopped before
# this job, start it after preflight and restore that stopped state at cleanup.
cluster_state="$(bounded_timeout 60 python3 tests/live/postgres/run.py --cluster-state)" || \
  fixed_error 'postgres-cluster-state-failed'
case "$cluster_state" in
  online) cluster_started=0 ;;
  down)
    cluster_started=1
    sudo_bounded pg_ctlcluster 16 main start >/dev/null 2>&1 || fixed_error 'postgres-start-failed'
    ;;
  *) fixed_error 'postgres-cluster-state-invalid' ;;
esac
verify_postgres_admin_preflight || fixed_error 'postgres-listener-policy-failed'

existing="$(admin_psql --quiet --tuples-only --no-align 2>/dev/null <<SQL
SELECT (SELECT count(*) FROM pg_database WHERE datname='$db_name') + (SELECT count(*) FROM pg_roles WHERE rolname='$db_role');
SQL
)" || fixed_error 'postgres-bootstrap-preflight-failed'
[[ "$existing" == 0 ]] || fixed_error 'postgres-resource-collision'
db_role_reserved=1
password="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
[[ "$password" =~ ^[0-9a-f]{64}$ ]] || fixed_error 'credential-generation-failed'

# Credentials cross only bounded psql stdin and one attached payload stdin
# envelope. The payload creates its own mode-0600 passfile on private tmpfs;
# only its PGPASSFILE path reaches native psql. No credential file is mounted
# or persisted by this controller.
if ! admin_psql --quiet --tuples-only --no-align >/dev/null 2>&1 <<SQL
SET log_statement = 'none';
SET password_encryption = 'scram-sha-256';
CREATE ROLE "$db_role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
\password $db_role
$password
$password
CREATE DATABASE "$db_name" OWNER "$db_role";
SQL
then
  fixed_error 'postgres-bootstrap-failed'
fi

role_policy="$(admin_psql --quiet --tuples-only --no-align 2>/dev/null <<SQL
SELECT CASE WHEN NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND d.datdba=r.oid THEN 'valid' ELSE 'invalid' END
  FROM pg_roles r JOIN pg_database d ON d.datname='$db_name' WHERE r.rolname='$db_role';
SQL
)" || fixed_error 'postgres-role-verification-failed'
[[ "$role_policy" == valid ]] || fixed_error 'postgres-role-policy-failed'

# The two harness files are sealed inside the manifest-verified rootfs.
# No checkout, staged source directory, or credential bind enters live.

# The rootfs live container shares only the host network namespace so its
# unprivileged UID can reach loopback PostgreSQL. Both families install a
# per-UID chain unconditionally and are structurally inspected before
# create/start. IPv6 loopback :5432 is allowed only when the selected
# service actually binds it; otherwise the IPv6 chain has no ACCEPT rule
# and drops all test-UID traffic. R92T-BACKEND-FINAL-01: the IPv4 chain
# also carries exactly one owner-scoped tcp-reset REJECT for the
# intentionally unavailable loopback endpoint 127.0.0.1:5433 ahead of the
# terminal DROP so the unavailable-host cases observe a deterministic
# connection refusal; the IPv6 chain never carries a 5433 rule because no
# case dials ::1:5433. Every other address and port defaults to DROP in
# both families.
if postgres_binds_ipv6_loopback; then
  ipv6_allow6='::1/128'
else
  ipv6_allow6=''
fi
install_live_firewall_family iptables firewall4_created 127.0.0.1/32 127.0.0.1/32 || \
  fixed_error 'ipv4-egress-setup-failed'
install_live_firewall_family ip6tables firewall6_created "$ipv6_allow6" '' || \
  fixed_error 'ipv6-egress-setup-failed'
verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32 || \
  fixed_error 'ipv4-egress-preflight-failed'
verify_effective_live_firewall_family ip6tables "$ipv6_allow6" '' || \
  fixed_error 'ipv6-egress-preflight-failed'

live_container="statekit-pg-live-$nonce"
container_must_be_absent "$live_container" || \
  fixed_error 'podman-container-name-collision'
live_env_names=(
  PATH LD_LIBRARY_PATH LC_ALL STATEKIT_ROOTFS_RUNTIME STATEKIT_PG_DATABASE STATEKIT_PG_USER
  STATEKIT_TEST_UID STATEKIT_TEST_GID STATEKIT_TOOL_ALLOWLIST
  STATEKIT_NO_SUDO_AUTHORIZATION STATEKIT_ROOTFS_MANIFEST_SHA256 STATEKIT_ROOTFS_ROLE
)
live_binds=(
  "/artifact/statekit=$statekit_artifact:ro"
  "/out=$run_dir/live-output:rw"
)
live_command=(/usr/bin/statekit-rootfs-preflight \
  /usr/bin/python3 -B /opt/statekit/repo/tests/live/postgres/run.py --run-cases)
test_command_timeout=650
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
[[ "$(sudo_bounded sha256sum -- "$statekit_artifact")" == \
   "$statekit_artifact_digest  $statekit_artifact" ]] || \
  fixed_error 'production-binary-artifact-digest-mismatch'
if ! live_container_id="$(podman_as_test_user create --rootfs \
  --name "$live_container" --interactive --network=host --userns=keep-id \
  --user "$test_uid:$test_gid" --read-only --read-only-tmpfs=false \
  --memory 4g --cpus 2 --pids-limit 256 --shm-size 64m --timeout 650 \
  --tmpfs /tmp:rw,nosuid,nodev,size=512m,mode=1777 \
  --tmpfs /dev/shm:rw,nosuid,nodev,noexec,size=64m,mode=1777 \
  --cap-drop=ALL --security-opt no-new-privileges \
  --ipc=private --pid=private --uts=private --no-hosts --no-hostname \
  --http-proxy=false --unsetenv-all \
  --env PATH=/usr/lib/postgresql/16/bin:/usr/bin:/bin \
  --env "LD_LIBRARY_PATH=$rootfs_library_path" --env LC_ALL=C \
  --env STATEKIT_ROOTFS_RUNTIME=1 \
  --env STATEKIT_PG_DATABASE="$db_name" --env STATEKIT_PG_USER="$db_role" \
  --env STATEKIT_TEST_UID="$test_uid" --env STATEKIT_TEST_GID="$test_gid" \
  --env STATEKIT_TOOL_ALLOWLIST=psql \
  --env STATEKIT_NO_SUDO_AUTHORIZATION=verified \
  --env STATEKIT_ROOTFS_MANIFEST_SHA256="$rootfs_manifest_sha256" \
  --env STATEKIT_ROOTFS_ROLE=live \
  --volume "$statekit_artifact:/artifact/statekit:ro,exec,nosuid,nodev,rprivate" \
  --volume "$run_dir/live-output:/out:rw,nosuid,nodev,noexec,rprivate" \
  --workdir /opt/statekit/repo \
  --label "io.statekit.rootfs.path=$rootfs_dir" \
  --label "io.statekit.rootfs.manifest-sha256=$rootfs_manifest_sha256" \
  --label "io.statekit.run.nonce=$run_nonce" \
  --label "io.statekit.phase=live" \
  "$rootfs_dir" "${live_command[@]}" 2>/dev/null)"; then
  create_failed_reconcile "$live_container" live "$rootfs_manifest_sha256" \
    'live-container-create-failed'
fi
container_receipt_claim "$live_container_id" "$live_container" live \
  "$rootfs_manifest_sha256" "$run_nonce" \
  || fixed_error 'container-ownership-receipt-invalid'

# Inspect effective namespaces, mounts, network, capabilities, resource limits,
# user mapping, environment keys, rootfs manifest, and the artifact digest
# before project code starts; the in-rootfs preflight rechecks the effective
# /proc and mountinfo state inside the container.
verify_podman_container "$live_container" host live_env_names live_binds \
  "$rootfs_dir" "$rootfs_manifest_sha256" 512m || \
  fixed_error 'live-container-policy-failed'
verify_rootfs_authoritative "$rootfs_dir" live-executable \
  "$rootfs_manifest_sha256" || fixed_error 'minimal-rootfs-verification-failed'
[[ "$(sudo_bounded sha256sum -- "$statekit_artifact")" == \
   "$statekit_artifact_digest  $statekit_artifact" ]] || \
  fixed_error 'production-binary-artifact-digest-mismatch'
# Exact effective canonical rules for both families are verified again
# immediately before the live payload starts, including the unavailable
# loopback endpoint's tcp-reset refusal.
verify_effective_live_firewall_family iptables 127.0.0.1/32 127.0.0.1/32 || \
  fixed_error 'ipv4-egress-preflight-failed'
verify_effective_live_firewall_family ip6tables "$ipv6_allow6" '' || \
  fixed_error 'ipv6-egress-preflight-failed'
# Reject any stale report before consuming the one-time credential envelope.
report_source="$run_dir/live-output/report.txt"
run_as_test_user "$ROOT" /usr/bin/python3 -c \
  'import os,sys; raise SystemExit(1 if os.path.lexists(sys.argv[1]) else 0)' \
  "$report_source" || fixed_error 'stale-report-rejected'
# password is controller-generated hex; shell printf is a builtin, not argv
# to an external process. Do not add a tty or logging to this stdin channel.
if ! printf '{"password":"%s"}\n' "$password" | \
    podman_as_test_user start --attach --interactive "$live_container" >/dev/null 2>&1; then
  password=''
  fixed_error 'postgres-live-gate-failed'
fi
password=''
[[ "$(podman_as_test_user inspect --format '{{.State.Status}}' "$live_container")" == exited \
   && "$(podman_as_test_user inspect --format '{{.State.ExitCode}}' "$live_container")" == 0 ]] || \
  fixed_error 'postgres-live-gate-failed'

report_source="$run_dir/live-output/report.txt"
sudo_bounded test -f "$report_source" && ! sudo_bounded test -L "$report_source" \
  || fixed_error 'postgres-report-unavailable'
[[ "$(sudo_bounded stat -c '%a:%h:%s' "$report_source")" =~ ^600:1:[1-9][0-9]*$ ]] || \
  fixed_error 'postgres-report-permission-policy-failed'

# Teardown is verified before report publication. The report itself is
# value-free and transferred out only after the payload container is
# removed, the run-owned role/database are independently confirmed absent,
# and the per-UID firewall rules are gone.
cleanup_all_containers || fixed_error 'container-cleanup-failed'
stop_test_user_processes || fixed_error 'test-user-process-cleanup-failed'
remove_firewall_family ip6tables "$firewall6_created" || \
  fixed_error 'ipv6-egress-cleanup-failed'
firewall6_created=0
remove_firewall_family iptables "$firewall4_created" || \
  fixed_error 'ipv4-egress-cleanup-failed'
firewall4_created=0
cleanup_database_and_role || fixed_error 'postgres-role-cleanup-failed'
cleanup_cluster || fixed_error 'postgres-cluster-cleanup-failed'
cleanup_exec_files || fixed_error 'exec-mount-cleanup-failed'

sudo_bounded chown "$RUNNER_UID:$RUNNER_GID" "$run_dir" "$run_dir/live-output" \
  || fixed_error 'report-transfer-failed'
chmod 0700 "$run_dir" "$run_dir/live-output" || fixed_error 'report-transfer-failed'
sudo_bounded chown --no-dereference "$RUNNER_UID:$RUNNER_GID" "$report_source" || \
  fixed_error 'report-transfer-failed'
chmod 0600 "$report_source" || fixed_error 'report-transfer-failed'
# Independent trusted-controller validation of the payload-produced report:
# strict single-link mode-0600 regular file, bounded size, exact value-free
# schema, ordered 20-case all-pass inventory, PostgreSQL 16/16.15, and the
# expected aggregate status. The validator shares no code with the payload
# harness and logs only a fixed category on failure, never report bytes.
bounded_timeout 30 python3 tests/live/postgres/validate_report.py "$report_source" || \
  fixed_error 'postgres-report-validation-failed'
install -m 0644 "$report_source" "$REPORT_PATH" || fixed_error 'report-publication-failed'
artifact_created=1
[[ -f "$REPORT_PATH" && ! -L "$REPORT_PATH" && -s "$REPORT_PATH" ]] || \
  fixed_error 'report-publication-failed'
[[ "$(stat -c '%a:%h' "$REPORT_PATH")" == '644:1' ]] || \
  fixed_error 'report-publication-failed'

# Drop the dedicated OS account and erase caches, temp files, and
# report staging data. The EXIT trap resumes incomplete teardown stages and
# removes the artifact if any cleanup boundary fails.
cleanup_identity_and_files
[[ "$cleanup_failed" == 0 ]] || fixed_error 'test-workspace-cleanup-failed'
