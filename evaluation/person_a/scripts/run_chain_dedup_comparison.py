#!/usr/bin/env python3
"""
E3 (chain correlation + episode-scoped dedup validation).

Fires each of the 5 documented CRITICAL chains 10 times sequentially
against the SAME `attacker` pod, each trial separated by more than 120s
(the correlation window), and records whether the chain alert re-fires
every time. Against the CURRENT code (episode-scoped dedup), expect 10/10
per chain.

For the high-value before/after comparison against the OLD, permanently-
deduped code (see EVALUATION_PLAN.md E3 and EVALUATION_REVIEW.md): that
part is intentionally a documented MANUAL procedure, not automated here.
Automating a git-checkout-and-rerun inside a script is the kind of thing
that's easy to get subtly wrong (stale .pyc files, wrong branch left
checked out, etc.) for a one-time comparison run. Run this exact same
script twice -- once against current `main`, once against the pre-fix
commit checked out to a scratch branch (see README.md for the exact
git commands) -- and pass --code-version to label which run produced which
CSV rows, then concatenate both CSVs for Fig. 8.

Usage:
    python3 evaluation/person_a/scripts/run_chain_dedup_comparison.py \\
        <server_logfile> <output_csv> --code-version new [--trials N]
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
# Must exceed the 120s correlation window so each trial is a genuinely
# independent episode by the window's own definition, not just "waiting
# long enough for the alert" -- 130s gives a 10s safety margin.
INTER_TRIAL_GAP_SECONDS = 130


def _run(cmd, timeout=15):
    # See run_ablation_full.py's _run -- a single transient timeout must
    # not crash a multi-hour N=10 run.
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def fire_t1059_t1552():
    """Two-hop chain: T1059 -> T1552."""
    _run('kubectl exec attacker -- bash -c "id && whoami"')
    time.sleep(2)
    _run('kubectl exec attacker -- bash -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" '
         'https://kubernetes.default.svc/api/v1/secrets"')


def fire_t1021_t1059_t1552():
    """Three-hop chain: T1021 -> T1059 -> T1552 (kubectl exec itself IS the
    T1021 leg; the exec'd command provides T1059+T1552)."""
    fire_t1059_t1552()  # the kubectl exec call above already generates T1021


def fire_t1059_t1610_t1552():
    """Four-hop chain: T1059 -> T1610 -> T1552 -- needs scan-targets."""
    _run('kubectl exec attacker -- bash -c "id && whoami"')
    time.sleep(1)
    ips = subprocess.run(
        ["kubectl", "get", "pods", "-l", "app=scan-targets", "-o", "wide", "--no-headers"],
        capture_output=True, text=True
    ).stdout.strip().split("\n")
    target_ips = [line.split()[5] for line in ips if line.strip()][:5]
    if len(target_ips) < 5:
        raise RuntimeError("need 5 scan-targets pod IPs -- apply week4/scan-targets.yaml first")
    procs = [subprocess.Popen(
        ["kubectl", "exec", "attacker", "--", "bash", "-c",
         f"exec 3<>/dev/tcp/{ip}/80; sleep 6; exec 3<&-"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) for ip in target_ips]
    for p in procs:
        # Same crash-resilience fix as _run() -- a single transient
        # timeout on one of the N parallel connections must not crash
        # the whole trial.
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    time.sleep(1)
    _run('kubectl exec attacker -- bash -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" '
         'https://kubernetes.default.svc/api/v1/secrets"')


def fire_t1059_t1548_t1611():
    """Escalation chain: T1059 -> T1548 -> T1611."""
    _run('kubectl exec attacker -- bash -c "id && whoami"')
    time.sleep(1)
    _run('kubectl exec attacker -- su root -c "id"')
    time.sleep(1)
    _run("kubectl exec attacker -- chroot / /bin/true")


def fire_t1611_t1552():
    """Breakout chain: T1611 -> T1552."""
    _run("kubectl exec attacker -- chroot / /bin/true")
    time.sleep(1)
    _run('kubectl exec attacker -- bash -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" '
         'https://kubernetes.default.svc/api/v1/secrets"')


CHAINS = {
    "T1059->T1552": ("T1059→T1552", fire_t1059_t1552),
    "T1021->T1059->T1552": ("T1021→T1059→T1552", fire_t1021_t1059_t1552),
    "T1059->T1610->T1552": ("T1059→T1610→T1552", fire_t1059_t1610_t1552),
    # These two used an ASCII "->" here, but causal_graph.py logs chain
    # alerts with a Unicode arrow ("T1059→T1548→T1611 ESCALATION CHAIN...",
    # "T1611→T1552 BREAKOUT CHAIN..." -- verified exact text in
    # src/causal_graph.py). "->" never appears in the real log line, so
    # this always timed out (false negative) until fixed -- the other
    # three CHAINS entries above already used the correct arrow.
    "T1059->T1548->T1611": ("T1059→T1548→T1611", fire_t1059_t1548_t1611),
    "T1611->T1552": ("T1611→T1552", fire_t1611_t1552),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("outfile")
    ap.add_argument("--code-version", required=True, choices=["old", "new"],
                     help="label only -- does NOT check out git commits for you; "
                          "see README.md for the manual old-vs-new procedure")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--gap", type=int, default=INTER_TRIAL_GAP_SECONDS,
                     help=f"seconds between trials, must exceed the 120s correlation "
                          f"window (default {INTER_TRIAL_GAP_SECONDS})")
    args = ap.parse_args()

    if args.gap <= 120:
        print(f"ERROR: --gap={args.gap} does not exceed the 120s correlation window -- "
              f"trials would not be independent episodes. Use > 120.")
        sys.exit(1)

    if not os.path.exists(args.logfile):
        print(f"ERROR: log file {args.logfile} does not exist. Is the server running?")
        sys.exit(1)

    write_header = not os.path.exists(args.outfile)
    with open(args.outfile, "a", newline="") as out_f:
        writer = csv.writer(out_f)
        if write_header:
            writer.writerow(["chain_type", "code_version", "trial", "fired", "latency_sec"])

        chain_keys = list(CHAINS.items())
        for chain_idx, (chain_key, (log_pattern, fire_fn)) in enumerate(chain_keys):
            print(f"\n=== {chain_key} (code_version={args.code_version}, "
                  f"{args.trials} trials, {args.gap}s apart) ===")
            for trial in range(1, args.trials + 1):
                pos = current_log_size(args.logfile)
                print(f"  [Trial {trial}] firing...")
                fire_fn()
                fired, line, _, elapsed = wait_for_pattern(args.logfile, pos, log_pattern,
                                                             DETECT_WAIT_SECONDS)
                print(f"    fired={int(fired)} (waited {elapsed:.1f}s)")
                writer.writerow([chain_key, args.code_version, trial, int(fired), round(elapsed, 2)])
                out_f.flush()
                if trial < args.trials:
                    print(f"    waiting {args.gap}s before next trial (must exceed 120s window)...")
                    time.sleep(args.gap)
            if chain_idx < len(chain_keys) - 1:
                # Several of these chains share overlapping trigger actions
                # -- e.g. T1021->T1059->T1552's own attack function IS
                # fire_t1059_t1552() (per its docstring: "the kubectl exec
                # call above already generates T1021"), and every T1059/
                # T1552-legged chain's own fire_fn opens with the same
                # "id && whoami" exec. Verified live: without a gap here,
                # the NEXT chain type's first trial started while the
                # PREVIOUS chain type's own episode was still open from the
                # correlator's point of view (same underlying legs, no real
                # elapsed time), so episode-scoped dedup correctly treated
                # it as a continuation, not a new episode, and didn't
                # re-fire -- a false "fired=0" that was actually the dedup
                # working as intended against a test-timing gap, not a
                # detection failure. Same fix as the same-chain trial gap:
                # exceed the 120s correlation window before starting a
                # different chain type too.
                print(f"    waiting {args.gap}s before next chain type (shared-trigger "
                      f"chains need episodes to fully close first)...")
                time.sleep(args.gap)

    print(f"\nDone. Results -> {args.outfile}")
    print("If this was the 'old' code_version run, concatenate with the 'new' run's "
          "CSV (same file, different --code-version) before generating Fig. 8.")


if __name__ == "__main__":
    main()
