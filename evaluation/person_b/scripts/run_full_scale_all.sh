#!/bin/bash
# Master orchestration for the full-scale (plan-spec) re-run of E4/E5/E6/E8.
# Designed to run unattended for 1.5-2+ hours: each stage is retried a
# bounded number of times on failure rather than aborting the whole
# sequence, and progress is logged with clear markers so a partial run can
# be diagnosed and resumed by stage rather than restarted from scratch.
set -o pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPTS_DIR="$REPO_DIR/evaluation/person_b/scripts"
PROGRESS_LOG="$REPO_DIR/evaluation/person_b/full_scale_run_progress.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$PROGRESS_LOG"; }

get_server_log() {
  PID=$(pgrep -f "src/server.py" | head -1)
  [ -z "$PID" ] && { echo ""; return; }
  readlink -f "/proc/$PID/fd/1" 2>/dev/null
}

ensure_server_up() {
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/ 2>/dev/null)
  if [ "$code" != "200" ]; then
    log "Server not responding (HTTP $code) -- running restart_cage.sh"
    bash "$REPO_DIR/restart_cage.sh" >> "$PROGRESS_LOG" 2>&1
  fi
}

retry_stage() {
  local name="$1"; shift
  local attempts=3
  for i in $(seq 1 $attempts); do
    log "=== STAGE: $name (attempt $i/$attempts) ==="
    ensure_server_up
    if "$@"; then
      log "=== STAGE OK: $name ==="
      return 0
    fi
    log "=== STAGE FAILED: $name (attempt $i/$attempts) -- will retry after a short pause ==="
    sleep 15
  done
  log "=== STAGE GAVE UP after $attempts attempts: $name -- continuing to next stage regardless ==="
  return 1
}

stage_e4_distribution() {
  local LOGFILE; LOGFILE=$(get_server_log)
  [ -z "$LOGFILE" ] && return 1
  python3 "$SCRIPTS_DIR/run_latency_batch.py" distribution --trials 20 --logfile "$LOGFILE"
}

stage_e4_connage() {
  python3 "$SCRIPTS_DIR/run_latency_batch.py" connage --ages 5,15,30,60,120
}

stage_e6() {
  python3 "$SCRIPTS_DIR/measure_scalability.py" --counts 1,2,4,8,16 --waves-per-n 10
}

stage_e5() {
  python3 "$SCRIPTS_DIR/measure_overhead.py" --idle-sec 300 --active-sec 600 --interval 5
}

stage_e8() {
  local LOGFILE; LOGFILE=$(get_server_log)
  [ -z "$LOGFILE" ] && return 1
  python3 "$SCRIPTS_DIR/inject_faults.py" --scenario all --reps 5 --settle-sec 20 --logfile "$LOGFILE"
}

log "########## FULL-SCALE RUN STARTED ##########"

retry_stage "E4 distribution (N=20)" stage_e4_distribution
retry_stage "E4 connection-age sweep (5,15,30,60,120)" stage_e4_connage
retry_stage "E6 scalability (10 waves/N)" stage_e6
retry_stage "E5 overhead (300/600/300s)" stage_e5
retry_stage "E8 fault injection (5 reps x 3 scenarios)" stage_e8

log "########## FULL-SCALE RUN COMPLETE ##########"

# Scale scan-targets back to a sane baseline after E6/E8 leave it at whatever
# the last stage's replica count was.
kubectl scale deployment scan-targets --replicas=5 >> "$PROGRESS_LOG" 2>&1

log "Cleanup done. See $PROGRESS_LOG for the full timeline."
