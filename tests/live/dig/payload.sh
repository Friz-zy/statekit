#!/usr/bin/env bash
# Fixed offline commands only; this script never enters the fetch container.
set -euo pipefail
fail() { printf '%s\n' 'in-container-preflight-failed' >&2; exit 1; }
[[ "$(id -u)" != 0 ]] || fail
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  [[ "$(awk -v key="$field:" '$1==key {print $2}' /proc/self/status)" == 0000000000000000 ]] || fail
done
[[ "$(awk '$1=="NoNewPrivs:" {print $2}' /proc/self/status)" == 1 ]] || fail
[[ "$(awk '$1=="Uid:" {print $2,$3,$4,$5}' /proc/self/status)" == "$(id -u) $(id -u) $(id -u) $(id -u)" ]] || fail
awk -v phase="${1:-}" '
  $5=="/" {if ($6 !~ /(^|,)ro(,|$)/) exit 1; root=1}
  $5=="/workspace" || $5=="/cache" {
    if ($6 !~ /(^|,)ro(,|$)/ || $6 !~ /(^|,)nosuid(,|$)/ || $6 !~ /(^|,)nodev(,|$)/ || $6 !~ /(^|,)noexec(,|$)/) exit 1
    if ($5=="/workspace") workspace=1
  }
  $5=="/tmp" {
    if ($6 !~ /(^|,)rw(,|$)/ || $6 !~ /(^|,)nosuid(,|$)/ || $6 !~ /(^|,)nodev(,|$)/) exit 1
    if (phase=="python" && $6 !~ /(^|,)noexec(,|$)/) exit 1
    if (phase!="python" && $6 ~ /(^|,)noexec(,|$)/) exit 1
    temp=1
  }
  $5 !~ /^\/(proc|sys|dev)(\/|$)/ && $5!="/" && $5!="/tmp" && $5!="/workspace" && $5!="/cache" && $5!="/etc/hosts" && $5!="/etc/hostname" && $5!="/etc/resolv.conf" && $5!="/etc/passwd" && $5!="/etc/group" {exit 1}
  END {if (!root || !workspace || !temp) exit 1}
' /proc/self/mountinfo || fail
[[ ! -e /run/podman/podman.sock && ! -e /var/run/docker.sock && ! -e /root/.ssh && ! -e /root/.aws ]] || fail
[[ ! -d /workspace/.git && ! -d /workspace/.gotmp ]] || fail
mkdir -p /tmp/home /tmp/go-cache /tmp/go
case "${1:-}" in
  python)
    /bin/bash -n /workspace/tests/live/dig/run.sh
    /bin/bash -n /workspace/tests/live/dig/payload.sh
    exec /usr/local/bin/python3 -I -m unittest discover -s /workspace/tests/live/dig -p test_orchestration.py -v
    ;;
  go-preflight|verify|contract)
    [[ "$(/usr/local/go/bin/go version)" == 'go version go1.26.6 linux/amd64' ]] || fail
    [[ "$GOTOOLCHAIN" == local && "$GOWORK" == off && "$GOENV" == off && "$GOPROXY" == off ]] || fail
    case "$1" in
      go-preflight) exit 0 ;;
      verify) exec /usr/local/go/bin/go mod verify ;;
      contract) exec /usr/local/go/bin/go test -tags=dns_contract -count=1 ./modules/exec/dig ./internal/cli ./tests/differential ;;
    esac
    ;;
  *) fail ;;
esac
