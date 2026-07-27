#!/bin/bash
# One-command environment restart for CAGE.
#
# Run this from WSL Ubuntu any time the kind cluster / CAGE server needs to
# come back up from cold — after a laptop sleep/resume, a Docker Desktop
# restart, or just starting a fresh session. Always tears down and
# recreates the kind cluster rather than trying to resuscitate a possibly
# stale one: this project hit a real, reproducible bug earlier where
# Docker Desktop restarts turn the audit-policy bind-mount source file
# into an empty directory, permanently breaking `docker start` on the old
# control-plane container. A clean recreate with a fresh scratch path
# sidesteps that class of problem entirely and only costs ~2-3 minutes.
#
# Does NOT touch any src/ file. Safe to run repeatedly.
#
# Usage:
#   bash restart_cage.sh            # full rebuild: cluster + Tetragon + pods + server
#   bash restart_cage.sh --no-cluster   # skip cluster rebuild, just restart the server
#                                        # (use when the cluster is already known-good)

set -e

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_LOG="$REPO_DIR/cage_server.log"
SKIP_CLUSTER=false
[ "$1" == "--no-cluster" ] && SKIP_CLUSTER=true

step() { echo ""; echo "=== $1 ==="; }

step "1/7 Checking Docker Desktop"
if ! docker info >/dev/null 2>&1; then
  echo "Docker Desktop is not running (or WSL integration isn't up yet)."
  echo "Start Docker Desktop on Windows, wait for it to say 'Running', then re-run this script."
  exit 1
fi
echo "Docker OK."

if [ "$SKIP_CLUSTER" = false ]; then
  step "2/7 Rebuilding kind cluster (cage-control-plane + 2 workers)"
  kind delete cluster --name cage >/dev/null 2>&1 || true
  # kind delete can leave a partially torn-down cluster behind (caught this
  # live: control-plane left Exited, workers gone, but `kind get clusters`
  # still listed "cage" and the next `kind create` correctly refused to
  # touch it) -- force-remove any straggler containers so create always
  # starts from a truly clean slate instead of failing on a half-deleted
  # cluster.
  docker rm -f cage-control-plane cage-worker cage-worker2 >/dev/null 2>&1 || true
  # A FIXED scratch filename here re-triggers the exact bug this comment is
  # about: Docker Desktop's bind-mount manager can leave the path behind as
  # a root-owned empty directory after a rotate/restart, which this
  # non-root WSL user then can't rm. Hit this live on a rerun of this very
  # script. Fix: a unique filename every run, so a poisoned leftover from a
  # PRIOR run is simply never touched or reused, only ever a fresh one.
  AUDIT_SCRATCH="/tmp/cage-audit-policy-restart-$(date +%s)-$$.yaml"
  KIND_SCRATCH="/tmp/kind-config-restart-$(date +%s)-$$.yaml"
  cp "$REPO_DIR/audit-policy.yaml" "$AUDIT_SCRATCH"
  # kind-config.yaml's extraMounts hostPath is a placeholder
  # (__AUDIT_POLICY_HOSTPATH_PLACEHOLDER__), not a real path -- it can't be,
  # since kind requires an absolute host path and this repo is checked out
  # at a different location on every contributor's machine. Substitute in
  # this run's own fresh scratch path here, every time.
  sed "s#__AUDIT_POLICY_HOSTPATH_PLACEHOLDER__#$AUDIT_SCRATCH#" "$REPO_DIR/kind-config.yaml" > "$KIND_SCRATCH"
  kind create cluster --config "$KIND_SCRATCH" --name cage

  step "3/7 Installing Tetragon"
  helm repo add cilium https://helm.cilium.io/ >/dev/null 2>&1 || true
  helm install tetragon cilium/tetragon -n kube-system
  kubectl -n kube-system rollout status ds/tetragon --timeout=180s

  step "4/7 Applying Tetragon tracing policies"
  kubectl apply -f "$REPO_DIR/k8s/tcp-connect-policy.yaml" -f "$REPO_DIR/k8s/capability-check-policy.yaml"

  step "5/7 Deploying attacker / legitimate-app / scan-targets, granting RBAC"
  kubectl apply -f - <<'PODEOF'
apiVersion: v1
kind: Pod
metadata:
  name: attacker
spec:
  containers:
  - name: attacker
    image: ubuntu:latest
    imagePullPolicy: IfNotPresent
    command: ["bash", "-c"]
    args: ["while true; do bash -c \"id && whoami\"; sleep 30; done"]
---
apiVersion: v1
kind: Pod
metadata:
  name: legitimate-app
spec:
  containers:
  - name: legitimate-app
    image: nginx:alpine
PODEOF
  kubectl apply -f "$REPO_DIR/week4/scan-targets.yaml"
  kubectl create clusterrolebinding attacker-secret-reader --clusterrole=cluster-admin --serviceaccount=default:default 2>/dev/null || true

  kubectl wait --for=condition=Ready pod/attacker --timeout=120s
  kubectl wait --for=condition=Ready pod/legitimate-app --timeout=120s
  kubectl wait --for=condition=Ready pod -l app=scan-targets --timeout=120s

  echo "Installing curl in attacker pod (needed by the attack-simulation scripts)..."
  kubectl exec attacker -- bash -c "apt-get update -qq && apt-get install -y -qq curl" >/dev/null 2>&1
else
  step "2-5/7 Skipped (--no-cluster): reusing existing cluster"
  kubectl get nodes >/dev/null 2>&1 || { echo "No reachable cluster found — run without --no-cluster."; exit 1; }
fi

step "6/7 Starting CAGE server"
pkill -9 -f "src/server.py" 2>/dev/null || true
sleep 2
cd "$REPO_DIR"
nohup python3 src/server.py > "$SERVER_LOG" 2>&1 &
disown
DEADLINE=$((SECONDS + 30))
until curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/ 2>/dev/null | grep -q 200; do
  if [ $SECONDS -ge $DEADLINE ]; then
    echo "Server did not come up within 30s -- check $SERVER_LOG"
    exit 1
  fi
  sleep 1
done

step "7/7 Status"
curl -s http://localhost:5000/api/health
echo ""
echo ""
echo "CAGE is up: http://localhost:5000"
echo "Server log: $SERVER_LOG"
echo ""
echo "Run an attack: bash week4/simulate_full_suite.sh"
