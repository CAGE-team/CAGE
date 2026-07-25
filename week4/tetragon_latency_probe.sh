#!/bin/bash
# Diagnostic tool, not part of the eval suite.
#
# Reproduces the finding behind the "Tetragon delivery latency" caveat in
# README.md / DEMO_GUIDE.md: `kubectl exec -n kube-system ds/tetragon -c
# tetragon -- tetra getevents` delivers events near-instantly on a freshly
# opened connection, but the identical command on a connection that's been
# open ~30+ seconds delivers the same kind of event ~30s late. Compares
# each event's own Tetragon-embedded capture timestamp (fast either way)
# against when the line actually became readable in the output (fast vs.
# slow) to isolate the delay to output buffering inside `tetra` itself,
# not eBPF capture, not CAGE's own Python code, and not node/daemonset-pod
# routing.
#
# Requires: an `attacker` pod already running, Tetragon installed.
set -e

echo "=== Node placement sanity check ==="
echo "attacker pod node: $(kubectl get pod attacker -o jsonpath='{.spec.nodeName}')"
echo "ds/tetragon exec resolves to: $(kubectl exec -n kube-system ds/tetragon -c tetragon -- hostname)"
echo "(if these differ, that alone would explain missing — not delayed — events)"
echo ""

run_trial() {
  local label="$1" age_seconds="$2" outfile="/tmp/tetragon_probe_${label}.jsonl"
  rm -f "$outfile"
  nohup kubectl exec -n kube-system ds/tetragon -c tetragon -- tetra getevents > "$outfile" 2>/dev/null &
  local pid=$!
  echo "[$label] connection opened, waiting ${age_seconds}s before firing..."
  sleep "$age_seconds"

  local pos fire_time
  pos=$(wc -c < "$outfile")
  fire_time=$(date +%s.%N)
  kubectl exec attacker -- bash -c "id && whoami" > /dev/null

  local matched=""
  for i in $(seq 1 40); do
    matched=$(tail -c +$((pos+1)) "$outfile" | grep -m1 '"binary":"/usr/bin/id"' || true)
    [ -n "$matched" ] && break
    sleep 1
  done
  local seen_time
  seen_time=$(date +%s.%N)

  if [ -z "$matched" ]; then
    echo "[$label] TIMEOUT — no match in 40s"
  else
    local capture_ts delivery_delay
    capture_ts=$(echo "$matched" | grep -oP '(?<="time":")[^"]*')
    delivery_delay=$(echo "$seen_time - $fire_time" | bc)
    echo "[$label] fired->visible: ${delivery_delay}s | Tetragon's own capture timestamp: $capture_ts"
  fi
  kill "$pid" 2>/dev/null || true
}

run_trial "fresh" 3
run_trial "aged" 35

echo ""
echo "If 'fresh' is fast (<2s) and 'aged' is slow (~28-30s), that reproduces"
echo "the connection-age-dependent buffering documented in README.md."
