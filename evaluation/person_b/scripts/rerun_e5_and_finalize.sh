#!/bin/bash
# One-shot re-run of just E5 (the only full-scale stage found corrupted --
# see common.py's find_server_pid() fix) followed by a full table/figure
# regeneration. Assumes the server is already up and healthy.
set -o pipefail
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PB_DIR="$REPO_DIR/evaluation/person_b"
LOG="$PB_DIR/rerun_e5.log"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG"; }

log "rerun_e5: starting E5 overhead measurement (300/600/300s, fixed PID lookup)..."
python3 "$PB_DIR/scripts/measure_overhead.py" --idle-sec 300 --active-sec 600 --interval 5 >> "$LOG" 2>&1
rc=$?
log "rerun_e5: measure_overhead.py exited rc=$rc"

log "rerun_e5: regenerating tables..."
python3 "$PB_DIR/plotting/build_tables.py" >> "$LOG" 2>&1

log "rerun_e5: regenerating figures..."
python3 "$PB_DIR/plotting/plot_latency_cdf.py" >> "$LOG" 2>&1
python3 "$PB_DIR/plotting/plot_latency_connage.py" >> "$LOG" 2>&1
python3 "$PB_DIR/plotting/plot_overhead.py" >> "$LOG" 2>&1
python3 "$PB_DIR/plotting/plot_fault_timeline.py" >> "$LOG" 2>&1

log "rerun_e5: DONE."
touch "$PB_DIR/E5_RERUN_COMPLETE"
