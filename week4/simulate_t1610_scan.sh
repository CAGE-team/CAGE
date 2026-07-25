#!/bin/bash
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "### Ensuring scan-target pods exist ###"
kubectl apply -f "$SCRIPT_DIR/scan-targets.yaml" > /dev/null
kubectl wait --for=condition=Ready pod -l app=scan-targets --timeout=60s > /dev/null 2>&1

echo "### Gathering distinct pod IPs to scan (need 5+ within 10s) ###"
mapfile -t TARGET_IPS < <(kubectl get pods -l app=scan-targets -o wide --no-headers | awk '{print $6}' | sort -u)

echo "Available targets:"
printf '%s\n' "${TARGET_IPS[@]}"

if [ "${#TARGET_IPS[@]}" -lt 5 ]; then
  echo "Not enough distinct pod IPs found (need 5, have ${#TARGET_IPS[@]})"
  exit 1
fi

SCAN_TARGETS=("${TARGET_IPS[@]:0:6}")
echo "### T1610 scan-like burst: attacker -> ${#SCAN_TARGETS[@]} distinct pods within a few seconds ###"

for ip in "${SCAN_TARGETS[@]}"; do
  kubectl exec attacker -- bash -c "exec 3<>/dev/tcp/${ip}/80; sleep 6; exec 3<&-" &
done
wait
echo "### DONE — connections held open ~6s so NetworkMonitor's 5s poll catches them ###"
