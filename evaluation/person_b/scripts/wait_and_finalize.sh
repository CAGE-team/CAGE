#!/bin/bash
# Waits for run_full_scale_all.sh to finish (polls every 30s, capped at 3h as
# a safety net so this never hangs forever), then automatically regenerates
# every figure/table against the completed full-scale data and writes a
# clear completion marker. Meant to be launched once, right after
# run_full_scale_all.sh itself, so the whole pipeline (collect -> analyze
# -> tabulate -> plot) finishes unattended without anyone needing to poll
# by hand.
set -o pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PB_DIR="$REPO_DIR/evaluation/person_b"
PROGRESS_LOG="$PB_DIR/full_scale_run_progress.log"
FINALIZE_LOG="$PB_DIR/finalize.log"

flog() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$FINALIZE_LOG"; }

flog "wait_and_finalize: waiting for run_full_scale_all.sh to exit..."
DEADLINE=$(( $(date +%s) + 3*60*60 ))
while pgrep -f "run_full_scale_all.sh" >/dev/null 2>&1; do
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    flog "wait_and_finalize: 3h safety cap hit -- run_full_scale_all.sh still alive, finalizing against whatever data exists so far rather than waiting forever."
    break
  fi
  sleep 30
done
flog "wait_and_finalize: run_full_scale_all.sh has exited (or safety cap hit). Last progress lines:"
tail -20 "$PROGRESS_LOG" >> "$FINALIZE_LOG" 2>&1

flog "wait_and_finalize: regenerating tables (build_tables.py)..."
python3 "$PB_DIR/plotting/build_tables.py" >> "$FINALIZE_LOG" 2>&1

flog "wait_and_finalize: regenerating figures..."
python3 "$PB_DIR/plotting/plot_latency_cdf.py" >> "$FINALIZE_LOG" 2>&1
python3 "$PB_DIR/plotting/plot_latency_connage.py" >> "$FINALIZE_LOG" 2>&1
python3 "$PB_DIR/plotting/plot_overhead.py" >> "$FINALIZE_LOG" 2>&1
python3 "$PB_DIR/plotting/plot_fault_timeline.py" >> "$FINALIZE_LOG" 2>&1

flog "wait_and_finalize: DONE. Tables in $PB_DIR/tables/, figures in $PB_DIR/figures/, all regenerated against full-scale data (or partial data if the safety cap was hit -- check the note above)."
touch "$PB_DIR/FULL_SCALE_COMPLETE"
