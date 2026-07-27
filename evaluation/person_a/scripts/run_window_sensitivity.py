#!/usr/bin/env python3
"""
E10 (correlation-window sensitivity) -- BLOCKED until the prerequisite in
EVALUATION_REVIEW.md Gap 3 is applied and approved.

The 120-second correlation window is a hardcoded inline literal
(`timedelta(seconds=120)`, twice in src/causal_graph.py), not a named
module constant, so lib/param_patch.py cannot override it the way it does
for the T1610/T1499/T1613 thresholds -- there's nothing to monkey-patch.
Running this script against an unmodified checkout will fail loudly with
an explicit RuntimeError from param_patch.apply_overrides() explaining
why, rather than silently measuring nothing.

Once CORRELATION_WINDOW_SECONDS exists as a real env-overridable constant
(see EVALUATION_REVIEW.md Gap 3 for the exact one-line change), this script
sweeps it and measures two things at each window size:
  1. Chain detection recall -- does a genuine chain (hops spread within the
     window) still get correlated?
  2. False-chain rate -- does an overly generous window incorrectly link
     two UNRELATED incidents on the same long-lived pod into a fabricated
     chain? (Fire T1059 alone, wait most of the window, then fire an
     unrelated T1552 from a completely different, later "incident" and
     check whether they get wrongly stitched together.)

Usage (after the prerequisite change is applied):
    CAGE_CORRELATION_WINDOW=60 ABLATION_MODE=fused \\
        python3 evaluation/person_a/scripts/launch_server_with_params.py
    python3 evaluation/person_a/scripts/run_window_sensitivity.py \\
        --window 60 <logfile> <outfile>
"""
import argparse
import csv
import os
import subprocess
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PERSON_A_DIR = os.path.dirname(SCRIPTS_DIR)
PROJECT_ROOT = os.path.dirname(os.path.dirname(PERSON_A_DIR))
sys.path.insert(0, PERSON_A_DIR)
sys.path.insert(0, PROJECT_ROOT)

from lib.wait_for_alert import wait_for_pattern, current_log_size  # noqa: E402

DETECT_WAIT_SECONDS = 60


def _check_prerequisite():
    """Fails loudly and specifically if the Gap 3 source change hasn't
    been applied yet, instead of silently testing nothing."""
    import src.causal_graph as causal_graph
    if not hasattr(causal_graph, "CORRELATION_WINDOW_SECONDS"):
        print("BLOCKED: src.causal_graph has no CORRELATION_WINDOW_SECONDS constant yet.")
        print("This experiment needs the one-line prerequisite change described in")
        print("EVALUATION_REVIEW.md, Gap 3, applied and approved first. Until then,")
        print("the 120s window is a hardcoded literal that cannot be swept.")
        sys.exit(1)


def _run(cmd, timeout=15):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    timeout=timeout)


def fire_t1059(): _run('kubectl exec attacker -- bash -c "id && whoami"')


def fire_t1552():
    _run('kubectl exec attacker -- bash -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" '
         'https://kubernetes.default.svc/api/v1/secrets"')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--window", type=int, required=True,
                     help="the window value (seconds) the server was just restarted with")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("logfile")
    ap.add_argument("outfile")
    args = ap.parse_args()

    _check_prerequisite()

    if not os.path.exists(args.logfile):
        print(f"ERROR: log file {args.logfile} does not exist. Is the server running?")
        sys.exit(1)

    write_header = not os.path.exists(args.outfile)
    with open(args.outfile, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["window_sec", "test_type", "trial", "gap_sec", "fired", "latency_sec"])

        # Test 1: genuine chain, hops spread at 80% of the window -- should detect.
        gap = int(args.window * 0.8)
        print(f"\n=== window={args.window}s: genuine chain, hops {gap}s apart (80% of window) ===")
        for trial in range(1, args.trials + 1):
            pos = current_log_size(args.logfile)
            fire_t1059()
            time.sleep(gap)
            fire_t1552()
            fired, _, _, elapsed = wait_for_pattern(args.logfile, pos, "T1059→T1552",
                                                      DETECT_WAIT_SECONDS)
            print(f"  [trial {trial}] gap={gap}s fired={int(fired)}")
            w.writerow([args.window, "genuine_chain_within_window", trial, gap, int(fired),
                        round(elapsed, 2)])

        # Test 2: hops spread at 120% of the window -- should NOT detect (window expired).
        gap_over = int(args.window * 1.2)
        print(f"\n=== window={args.window}s: hops {gap_over}s apart (120% of window, "
              f"should NOT correlate) ===")
        for trial in range(1, args.trials + 1):
            pos = current_log_size(args.logfile)
            fire_t1059()
            time.sleep(gap_over)
            fire_t1552()
            fired, _, _, elapsed = wait_for_pattern(args.logfile, pos, "T1059→T1552",
                                                      DETECT_WAIT_SECONDS)
            print(f"  [trial {trial}] gap={gap_over}s fired={int(fired)}")
            w.writerow([args.window, "unrelated_beyond_window", trial, gap_over, int(fired),
                        round(elapsed, 2)])

    print(f"\nDone. Results -> {args.outfile}")


if __name__ == "__main__":
    main()
