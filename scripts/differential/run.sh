#!/usr/bin/env bash
# Twin-container differential driver (plans/testing.md, init.md section 26).
#
# Usage: run.sh <distro-image-ref> <suite...>
# Environment:
#   SALT_VERSION      pinned Salt release (parsed from references/salt.lock)
#   STATEKIT_BIN      path to the compiled binary (default dist/statekit)
#
# Container A: distro base + pip-installed Salt at the pinned version.
# Container B: same base + StateKit binary.
set -euo pipefail

IMAGE="$1"; shift
SCENARIOS="${SCENARIOS:-scripts/differential/scenarios.yaml}"
NORMALIZE="${NORMALIZE:-scripts/differential/normalize.py}"
STATEKIT_BIN="${STATEKIT_BIN:-dist/statekit}"
SALT_VERSION="${SALT_VERSION:?SALT_VERSION must be set}"

WORK="$(mktemp -d)"
trap 'docker rm -f sk-diff-salt sk-diff-kit >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

echo "[differential] starting twin containers for $IMAGE"
docker run -d --name sk-diff-salt "$IMAGE" sleep infinity
docker run -d --name sk-diff-kit "$IMAGE" sleep infinity

echo "[differential] installing Salt $SALT_VERSION in container A"
docker exec sk-diff-salt sh -c \
  "command -v pip3 >/dev/null 2>&1 || { apt-get update -qq && apt-get install -y -qq python3-pip || apk add --no-cache python3 py3-pip; }"
# salt needs a venv on newer pip (PEP 668); best-effort across distros.
docker exec sk-diff-salt sh -c "
  if pip3 install --help 2>/dev/null | grep -q -- --break-system-packages; then
    pip3 install --break-system-packages 'salt==${SALT_VERSION}'
  else
    pip3 install 'salt==${SALT_VERSION}'
  fi" >/dev/null

docker cp "$STATEKIT_BIN" sk-diff-kit:/usr/local/bin/statekit
docker exec sk-diff-kit chmod +x /usr/local/bin/statekit

python3 - "$SCENARIOS" >"$WORK/plan.json" <<'PY'
import json, sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
print(json.dumps(doc["scenarios"]))
PY

total=0; failures=0
for id in $(python3 -c "import json;print(' '.join(s['id'] for s in json.load(open('$WORK/plan.json'))))"); do
    total=$((total+1))
    scenario=$(python3 -c "
import json
scenarios = json.load(open('$WORK/plan.json'))
print(json.dumps(next(s for s in scenarios if s['id'] == '$id')))
")

    # Per-side temp dirs keep both environments isolated and equivalent.
    docker exec sk-diff-salt sh -c 'mkdir -p /tmp/skdiff'
    docker exec sk-diff-kit   sh -c 'mkdir -p /tmp/skdiff'

    # Prerun steps execute identically on both sides before the scenario.
    prerun_count=$(echo "$scenario" | python3 -c "import json,sys;print(len(json.load(sys.stdin).get('prerun', [])))")
    for i in $(seq 0 $((prerun_count-1))); do
        step_fun=$(echo "$scenario" | python3 -c "import json,sys;print(json.load(sys.stdin)['prerun'][$i]['fun'])")
        step_args=$(echo "$scenario" | python3 -c "
import json, sys
args = json.load(sys.stdin)['prerun'][$i]['args']
print(' '.join(f'{k}={v}' for k, v in args.items()))")
        kind=$(echo "$scenario" | python3 -c "import json,sys;print(json.load(sys.stdin)['prerun'][$i].get('kind','state'))")
        case "$kind" in
            state)
                docker exec sk-diff-salt salt-call --local --out=json state.single "$step_fun" $step_args >/dev/null || true
                docker exec sk-diff-kit /usr/local/bin/statekit state "$step_fun" $step_args >/dev/null || true
                ;;
        esac
    done

    fun=$(echo "$scenario" | python3 -c "import json,sys;print(json.load(sys.stdin)['fun'])")
    kind=$(echo "$scenario" | python3 -c "import json,sys;print(json.load(sys.stdin).get('kind','state'))")
    args_kv=$(echo "$scenario" | python3 -c "
import json, sys
args = json.load(sys.stdin)['args']
print(' '.join(f'{k}={v}' for k, v in args.items()))")
    args_json=$(echo "$scenario" | python3 -c "
import json, sys
print(json.dumps(json.load(sys.stdin)['args']))")

    echo "[differential] scenario: $id"
    set +e
    if [ "$kind" = "state" ]; then
        docker exec sk-diff-salt salt-call --local --out=json state.single "$fun" $args_kv \
            >"$WORK/salt.json" 2>"$WORK/salt.err"
        s_rc=$?
        docker exec sk-diff-kit /usr/local/bin/statekit state "$fun" --config "$args_json" --out json \
            >"$WORK/kit.json" 2>"$WORK/kit.err"
        k_rc=$?
    else
        name=$(echo "$scenario" | python3 -c "import json,sys;print(json.load(sys.stdin)['args'].get('name',''))")
        docker exec sk-diff-salt salt-call --local --out=json "$fun" "$name" \
            >"$WORK/salt.json" 2>"$WORK/salt.err"
        s_rc=$?
        docker exec sk-diff-kit /usr/local/bin/statekit exec "$fun" --config "$args_json" --out json \
            >"$WORK/kit.json" 2>"$WORK/kit.err"
        k_rc=$?
    fi
    set -e

    if [ "$s_rc" != "$k_rc" ]; then
        echo "[differential] MISMATCH exit codes: salt=$s_rc statekit=$k_rc"
        failures=$((failures+1))
        continue
    fi

    echo "$scenario" >"$WORK/scenario.json"
    if python3 "$NORMALIZE" "$WORK/scenario.json" "$WORK/salt.json" "$WORK/kit.json"; then
        :
    else
        echo "[differential] see raw payloads: $WORK/{salt,kit}.json"
        failures=$((failures+1))
    fi
done

echo "[differential] parity: $((total-failures))/$total scenarios"
[ "$failures" -eq 0 ]
