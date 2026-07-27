#!/usr/bin/env python3
"""
E7 (threshold sensitivity sweep) + E9 (evasion boundary testing), merged --
they share the same "fire N units of attack behavior" primitives but vary
different independent variables, so they're two modes of one script rather
than two separate ones with duplicated attack logic.

  --mode sweep    (E7): fixed, obviously-over-threshold attack intensity
                   (8 connections / 30 execs / 12 RBAC reads), threshold
                   value varied via launch_server_with_params.py between
                   runs. Answers: "at what threshold does detection
                   appear/disappear?"

  --mode evasion  (E9): DEFAULT thresholds (no server restart needed --
                   run against a normal `python3 src/server.py`), attack
                   intensity varied to sit exactly at vs. one-under each
                   threshold. Answers: "can an attacker who knows the
                   default thresholds stay just under them?"

For --mode sweep, restart the server between threshold values using:
    T1610_BURST_THRESHOLD=<value> ABLATION_MODE=fused \\
        python3 evaluation/person_a/scripts/launch_server_with_params.py
(same env-var-per-technique pattern for T1499_FORKBOMB_THRESHOLD and
T1613_RBAC_THRESHOLD -- see lib/param_patch.py). This script prompts you
to confirm before each threshold value, same convention as
run_ablation_full.py / the original run_ablation.py.

Usage:
    python3 evaluation/person_a/scripts/run_parameter_sensitivity.py \\
        --mode sweep --technique T1610 --threshold 3 <logfile> <outfile>
    python3 evaluation/person_a/scripts/run_parameter_sensitivity.py \\
        --mode evasion <logfile> <outfile>
"""
import argparse
import csv
import os
import subprocess
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PERSON_A_DIR = os.path.dirname(SCRIPTS_DIR)
sys.path.insert(0, PERSON_A_DIR)

from lib.wait_for_alert import wait_for_pattern, current_log_size  # noqa: E402

DETECT_WAIT_SECONDS = 60


def _run(cmd, timeout=20):
    # See run_ablation_full.py's _run -- a single transient timeout must
    # not crash a multi-hour N=10 run.
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def fire_n_connections(n):
    """T1610: n distinct-destination connection attempts against
    scan-targets (needs >= n scan-targets pods; the deployment currently
    ships 5 replicas -- scale it up first if testing n > 5, e.g.
    `kubectl scale deployment scan-targets --replicas=8`)."""
    ips = subprocess.run(
        ["kubectl", "get", "pods", "-l", "app=scan-targets", "-o", "wide", "--no-headers"],
        capture_output=True, text=True
    ).stdout.strip().split("\n")
    target_ips = [line.split()[5] for line in ips if line.strip()]
    if len(target_ips) < n:
        raise RuntimeError(f"need {n} scan-targets pod IPs, only found {len(target_ips)} -- "
                            f"scale the deployment up first")
    procs = [subprocess.Popen(
        ["kubectl", "exec", "attacker", "--", "bash", "-c",
         f"exec 3<>/dev/tcp/{ip}/80; sleep 6; exec 3<&-"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for ip in target_ips[:n]]
    for p in procs:
        # Same crash-resilience fix as _run() -- a single transient
        # timeout on one of the N parallel connections must not crash
        # the whole trial (or the whole multi-hour run). Verified live:
        # this exact gap crashed a 50-minute E9 run on trial 9 of 10.
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def fire_n_execs(n):
    """T1499: approximately n exec events from the same pod within the
    fork-bomb window -- treat this as "roughly n", not exact. There is
    real overhead beyond the /bin/true loop itself (at minimum the
    "bash" process kubectl exec launches), but live measurement showed
    the total overhead was NOT reliably exactly 1: switching from a
    `$(seq 1 N)` loop (2 known extra processes: bash + seq) to a pure
    bash-arithmetic `for ((i=0; i<N; i++))` loop (which should only add
    "bash" itself) still produced the same "+2 from loop_count" result in
    repeated, carefully-spaced live tests, and the discrepancy wasn't
    pinned down further within a reasonable time budget. Callers needing
    a precise sub-threshold boundary should use a comfortable margin
    (see run_parameter_sensitivity.py's JUST_UNDER_MARGIN for T1499)
    rather than trusting this to land on an exact count."""
    loop_count = max(0, n - 1)
    _run(f"kubectl exec attacker -- bash -c 'for ((i=0; i<{loop_count}; i++)); do /bin/true; done'",
         timeout=max(15, n // 2))


def fire_n_rbac_reads(n):
    """T1613: n get-clusterroles calls -- note the real detector fires on
    count == threshold exactly (see src/audit_log_consumer.py's
    _track_rbac_discovery), not >=, so testing n = threshold-1 (never
    reaches it) and n = threshold (hits it exactly) are the meaningful
    pair; n = threshold+1 alone would NOT trigger it and should not be
    mistaken for an evasion success."""
    for _ in range(n):
        _run('kubectl exec attacker -- bash -c \'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
             'curl -s -k -H "Authorization: Bearer $TOKEN" '
             'https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles\' > /dev/null 2>&1',
             timeout=5)


ATTACK_PRIMITIVES = {
    "T1610": (fire_n_connections, "T1610", 5),        # (fn, log_pattern, default_threshold)
    "T1499": (fire_n_execs, "T1499", 25),
    "T1613": (fire_n_rbac_reads, "T1613", 10),
}


# CAUTION (found live while validating run_detection_accuracy.py's benign
# T1610 control): NetworkMonitor keeps re-emitting "T1610: ... burst from
# attacker" for several seconds after a single qualifying burst (the burst
# condition stays true across multiple poll cycles), so a trial can catch a
# residual re-fire from the PRECEDING trial rather than genuinely
# triggering its own. This does NOT corrupt evasion mode's boundary claim
# here, because ATTACK_PRIMITIVES processes T1610 first and "just_under"
# always runs before "at_threshold" for the same technique -- the weaker
# trial can never inherit a residual re-fire from a not-yet-run stronger
# one. It WOULD corrupt a benign-vs-malicious comparison (see
# run_detection_accuracy.py's BENIGN_LOG_PATTERN fix) -- not a concern here
# since every trial in this file is malicious-only.
# T1613 fires on count == RBAC_DISCOVERY_THRESHOLD exactly within a 30s
# rolling window (src/audit_log_consumer.py's _track_rbac_discovery). A
# short gap between trials is a bigger risk here than for T1499: for
# "just_under" (n=9, expected to NEVER fire), a short gap lets trial
# N+1's reads accumulate on top of trial N's still-open window, so the
# cumulative count can cross exactly 10 mid-trial and produce a FALSE
# fired=1 that looks like a failed evasion when each trial's own 9
# reads never actually reached the threshold alone. 32s (window + 2s
# margin) keeps trials genuinely independent.
INTER_TRIAL_GAP = {"T1613": 32}
DEFAULT_INTER_TRIAL_GAP = 2


def run_trials(technique, n_value, logfile, writer, trials, extra_cols, out_f=None):
    fn, pattern, _ = ATTACK_PRIMITIVES[technique]
    fired_count = 0
    for trial in range(1, trials + 1):
        pos = current_log_size(logfile)
        print(f"    [trial {trial}] firing {technique} at n={n_value}...")
        fn(n_value)
        fired, _, _, elapsed = wait_for_pattern(logfile, pos, pattern, DETECT_WAIT_SECONDS)
        fired_count += int(fired)
        writer.writerow([*extra_cols, trial, n_value, int(fired), round(elapsed, 2)])
        # Flush after every trial, not just at the end -- see
        # run_ablation_full.py's _run comment: an uncaught transient
        # timeout crashed a 35-minute run with zero results saved.
        if out_f is not None:
            out_f.flush()
        time.sleep(INTER_TRIAL_GAP.get(technique, DEFAULT_INTER_TRIAL_GAP))
    return fired_count


def mode_sweep(args):
    if args.technique not in ATTACK_PRIMITIVES:
        print(f"ERROR: --technique must be one of {list(ATTACK_PRIMITIVES)}")
        sys.exit(1)
    _, pattern, default_threshold = ATTACK_PRIMITIVES[args.technique]
    attack_n = args.attack_intensity or (default_threshold + 3)  # comfortably over any tested threshold

    print(f"=== Sweep point: {args.technique}, threshold={args.threshold}, "
          f"attack intensity={attack_n} ===")
    print(f"Confirm the server is running via launch_server_with_params.py with "
          f"{_env_var_for(args.technique)}={args.threshold} before continuing.")
    if args.yes:
        print("(--yes given, skipping interactive confirmation)")
    else:
        input("Press ENTER once confirmed...")

    write_header = not os.path.exists(args.outfile)
    with open(args.outfile, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["mode", "technique", "independent_var", "trial", "attack_intensity",
                        "fired", "latency_sec"])
        fired = run_trials(args.technique, attack_n, args.logfile, w, args.trials,
                            ["sweep", args.technique, args.threshold], out_f=f)
    print(f"\n{fired}/{args.trials} fired at threshold={args.threshold}, "
          f"attack intensity={attack_n}. Results -> {args.outfile}")


def mode_evasion(args):
    print("=== Evasion boundary testing (default thresholds, no server restart needed) ===")
    print("Confirm a server is running with DEFAULT thresholds (plain "
          "`python3 src/server.py` or launch_server_with_params.py with no overrides).")
    if args.yes:
        print("(--yes given, skipping interactive confirmation)")
    else:
        input("Press ENTER once confirmed...")

    write_header = not os.path.exists(args.outfile)
    with open(args.outfile, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["mode", "technique", "independent_var", "trial", "attack_intensity",
                        "fired", "latency_sec"])

        # T1499's just_under uses a wider margin than threshold-1. Its attack
        # primitive (fire_n_execs) fires a single kubectl-exec'd bash loop,
        # and live testing showed the wrapper process overhead was NOT
        # reliably exactly 1 -- repeated live measurements (across two
        # different loop implementations, with generous inter-test spacing
        # to rule out dedup/window contamination) consistently showed
        # loop_count=23 producing a detected count of 25, not the expected
        # 24, and the exact source of the extra process was not pinned down
        # within a reasonable time budget. Rather than assert a precise
        # "one under" boundary the live evidence doesn't actually support,
        # T1499 tests a COMFORTABLY-under value instead -- still a genuine
        # evasion-boundary data point (proves sub-threshold traffic evades
        # detection), just not claiming single-unit precision. T1610 and
        # T1613 don't have this issue (verified live, exact threshold-1
        # boundary behaves correctly for both) and keep the precise form.
        JUST_UNDER_MARGIN = {"T1499": 10}
        for technique, (fn, pattern, threshold) in ATTACK_PRIMITIVES.items():
            margin = JUST_UNDER_MARGIN.get(technique, 1)
            for boundary, n_value in (("just_under", threshold - margin), ("at_threshold", threshold)):
                print(f"\n--- {technique}: {boundary} (n={n_value}, default threshold={threshold}) ---")
                fired = run_trials(technique, n_value, args.logfile, w, args.trials,
                                    ["evasion", technique, boundary], out_f=f)
                print(f"  {fired}/{args.trials} fired")

    print(f"\nDone. Results -> {args.outfile}")
    print("Expected: 'just_under' rows should show 0 fired (successful evasion at the "
          "current default), 'at_threshold' rows should show N/N fired -- report both "
          "honestly, this IS the boundary characterization, not a failure.")


def _env_var_for(technique):
    return {"T1610": "T1610_BURST_THRESHOLD", "T1499": "T1499_FORKBOMB_THRESHOLD",
            "T1613": "T1613_RBAC_THRESHOLD"}[technique]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["sweep", "evasion"])
    ap.add_argument("--technique", choices=list(ATTACK_PRIMITIVES), help="required for --mode sweep")
    ap.add_argument("--threshold", type=int, help="the threshold value the server was just "
                                                    "restarted with (required for --mode sweep)")
    ap.add_argument("--attack-intensity", type=int, default=None,
                     help="override the fixed attack size used in sweep mode (default: "
                          "threshold+3, comfortably over anything being tested)")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--yes", action="store_true",
                     help="skip the interactive confirm-the-server-is-ready prompt (for "
                          "non-interactive/automated runs -- verify the server state "
                          "yourself first, e.g. via curl .../api/health)")
    ap.add_argument("logfile")
    ap.add_argument("outfile")
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        print(f"ERROR: log file {args.logfile} does not exist. Is the server running?")
        sys.exit(1)

    if args.mode == "sweep":
        if args.technique is None or args.threshold is None:
            print("ERROR: --mode sweep requires --technique and --threshold")
            sys.exit(1)
        mode_sweep(args)
    else:
        mode_evasion(args)


if __name__ == "__main__":
    main()
