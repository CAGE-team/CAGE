#!/usr/bin/env python3
"""
E2 (cross-layer ablation study, extended to all 11 techniques).

New file -- does NOT modify run_ablation.py. Reuses its confirm-between-
conditions pattern (you restart the server with a different ABLATION_MODE
between runs of this script) but extends technique coverage from 4 to all
11, and fixes run_ablation.py's T1610 entry, which uses a stale hardcoded
IP and a single connection that cannot satisfy the current 5-destination
burst requirement (see EVALUATION_REVIEW.md, Gap 9) -- this version uses
the same scan-targets burst pattern already proven working in
simulate_full_suite.sh / simulate_t1610_scan.sh instead.

Usage:
    python3 evaluation/person_a/scripts/run_ablation_full.py \\
        <condition_name> <server_logfile> <output_csv> [--trials N]

    condition_name is a label only (tetragon_only|audit_only|fused) -- start
    the server with the matching ABLATION_MODE env var yourself first, same
    as the original run_ablation.py.

Prerequisites in the cluster before running:
    - `attacker` pod (existing)
    - `week4/scan-targets.yaml` applied (for T1610)
    - `week4/benign-app.yaml` NOT required here (E2 is attack-only; benign
      trials are E1's job, via run_detection_accuracy.py)
"""
import argparse
import csv
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # person_a dir
from lib.wait_for_alert import wait_for_pattern, current_log_size  # noqa: E402

DETECT_WAIT_SECONDS = 60  # matches the widened window applied to run_ablation.py
                          # this session -- see README.md's Evaluation section
                          # for why (Tetragon connection-age latency effect)

# T1613 fires on count == RBAC_DISCOVERY_THRESHOLD exactly within a 30s
# rolling window (src/audit_log_consumer.py's _track_rbac_discovery) -- a
# short gap between trials means trial N+1's reads land in the SAME
# still-open window as trial N's, pushing the count past 10 (never exactly
# 10 again) instead of starting fresh, so it silently stops firing after
# the first trial. Verified live: default 3s gap produced fired=1 on trial
# 1 then fired=0 on trial 2 against an unmodified detector -- not a
# detection bug, a test-timing bug. 32s (window + 2s margin) fixes it,
# same "exceed the window" pattern as E3's 130s-vs-120s chain gap.
DEFAULT_INTER_TRIAL_GAP = 3
INTER_TRIAL_GAP = {"T1613": 32}


def _run(cmd, timeout=15):
    # A single transient kubectl/network hiccup (a call taking a bit over
    # its timeout) must not crash a run that's an hour+ into real N=10
    # data collection -- verified live: an uncaught TimeoutExpired here
    # killed a 35-minute E1 run with zero results saved. Treat a timeout
    # as "this one call didn't complete" and let the caller's own
    # wait_for_pattern-based fired/not-fired check be the source of truth,
    # not a crash.
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def attack_t1059():
    _run('kubectl exec attacker -- bash -c "id && whoami"')


def attack_t1021():
    _run('kubectl exec attacker -- echo "trial"')


def attack_t1552():
    _run('kubectl exec attacker -- bash -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H \\"Authorization: Bearer \\$TOKEN\\" '
         'https://kubernetes.default.svc/api/v1/namespaces/default/secrets/db-credentials"')


def attack_t1610():
    """5-distinct-destination burst against scan-targets, matching the
    already-verified pattern in simulate_t1610_scan.sh -- NOT the broken
    single-connection version in the original run_ablation.py."""
    ips = subprocess.run(
        ["kubectl", "get", "pods", "-l", "app=scan-targets", "-o", "wide", "--no-headers"],
        capture_output=True, text=True
    ).stdout.strip().split("\n")
    target_ips = [line.split()[5] for line in ips if line.strip()]
    if len(target_ips) < 5:
        raise RuntimeError(
            f"only {len(target_ips)} scan-targets pod IPs found (need 5) -- "
            f"apply week4/scan-targets.yaml and wait for it to be Ready first"
        )
    procs = []
    for ip in target_ips[:5]:
        p = subprocess.Popen(
            ["kubectl", "exec", "attacker", "--", "bash", "-c",
             f"exec 3<>/dev/tcp/{ip}/80; sleep 6; exec 3<&-"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(p)
    for p in procs:
        # Same crash-resilience fix as _run() -- a single transient
        # timeout on one of the N parallel connections must not crash
        # the whole trial.
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()


def attack_t1611():
    _run("kubectl exec attacker -- chroot / /bin/true")


def attack_t1548():
    _run('kubectl exec attacker -- su root -c "id"')


def attack_t1496():
    _run('kubectl exec attacker -- bash -c '
         '"cp /bin/true /tmp/xmrig_eval && chmod +x /tmp/xmrig_eval && /tmp/xmrig_eval"')


def attack_t1499():
    _run("kubectl exec attacker -- bash -c 'for i in $(seq 1 30); do /bin/true; done'", timeout=20)


def attack_t1613():
    # RBAC_DISCOVERY_THRESHOLD fires on == 10 reads exactly (see
    # src/audit_log_consumer.py's _track_rbac_discovery) -- not >=, so
    # firing exactly 10 matters; 11+ without hitting exactly 10 would
    # silently never trigger. Matches simulate_full_suite.sh's own count.
    for _ in range(10):
        _run('kubectl exec attacker -- bash -c \'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); '
             'curl -s -k -H "Authorization: Bearer $TOKEN" '
             'https://kubernetes.default.svc/apis/rbac.authorization.k8s.io/v1/clusterroles\' > /dev/null 2>&1',
             timeout=5)


def attack_t1548_priv_pod(trial_id):
    # Unique pod name per trial -- kubectl apply against an unchanged,
    # already-existing pod issues verb=patch not verb=create, and
    # _check_privileged_pod_spec requires verb=="create" (see
    # week4/simulate_full_suite.sh's own fix for this exact issue).
    pod_name = f"ablation-privpod-{trial_id}-{os.getpid()}"
    manifest = (
        f'apiVersion: v1\nkind: Pod\nmetadata:\n  name: {pod_name}\n'
        f'  namespace: default\nspec:\n  containers:\n  - name: privesc\n'
        f'    image: busybox\n    command: ["sleep", "60"]\n'
        f'    securityContext:\n      privileged: true\n'
    )
    tmp_path = f"/tmp/{pod_name}.yaml"
    with open(tmp_path, "w") as f:
        f.write(manifest)
    _run(f"kubectl apply -f {tmp_path}")
    return pod_name


def cleanup_t1548_priv_pod(pod_name):
    _run(f"kubectl delete pod {pod_name} --ignore-not-found=true --wait=false", timeout=10)


def attack_t1548_005(trial_id):
    binding_name = f"ablation-rbac-{trial_id}-{os.getpid()}"
    role_name = f"ablation-godmode-{trial_id}-{os.getpid()}"
    _run(f"kubectl create clusterrolebinding {binding_name} "
         f"--clusterrole=cluster-admin --serviceaccount=default:legitimate-app")
    _run(f'kubectl create clusterrole {role_name} --verb="*" --resource="*"')
    return binding_name, role_name


def cleanup_t1548_005(binding_name, role_name):
    _run(f"kubectl delete clusterrolebinding {binding_name} --ignore-not-found=true", timeout=10)
    _run(f"kubectl delete clusterrole {role_name} --ignore-not-found=true", timeout=10)


# technique -> (check_pattern_in_log, attack_fn, needs_trial_id)
TECHNIQUES = {
    "T1059": ("T1059", attack_t1059, False),
    "T1021": ("T1021", attack_t1021, False),
    "T1552": ("T1552", attack_t1552, False),
    "T1610": ("T1610", attack_t1610, False),
    "T1611": ("T1611", attack_t1611, False),
    "T1548": ("T1548", attack_t1548, False),
    "T1496": ("T1496", attack_t1496, False),
    "T1499": ("T1499", attack_t1499, False),
    "T1613": ("T1613", attack_t1613, False),
    # These two techniques' log text does NOT contain their technique code
    # (see src/causal_graph.py's _check_privileged_pod_spec /
    # _check_rbac_abuse) -- "T1548-PRIV-POD" logs as "T1548: privileged pod
    # created ..." (indistinguishable by code from plain T1548 without this
    # substring) and "T1548.005" logs as "RBAC-ABUSE: ...". The alert
    # object's own "rule" field IS correct in both cases; only the free-text
    # log line omits it. Verified live: searching for the technique code
    # literally always timed out (false negative) until this fix.
    "T1548-PRIV-POD": ("privileged pod created", None, "priv_pod"),
    "T1548.005": ("RBAC-ABUSE", None, "rbac005"),
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("condition", choices=["tetragon_only", "audit_only", "fused"])
    ap.add_argument("logfile")
    ap.add_argument("outfile")
    ap.add_argument("--trials", type=int, default=10)
    ap.add_argument("--yes", action="store_true",
                     help="skip the interactive confirm-the-server-mode prompt (for "
                          "non-interactive/automated runs -- verify the ON/OFF pattern "
                          "yourself first, e.g. via curl .../api/health, before using this)")
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        print(f"ERROR: log file {args.logfile} does not exist. Is the server running?")
        sys.exit(1)

    write_header = not os.path.exists(args.outfile)
    with open(args.outfile, "a", newline="") as out_f:
        writer = csv.writer(out_f)
        if write_header:
            writer.writerow(["condition", "technique", "trial", "fired", "latency_sec"])

        print(f"=== Ablation condition: {args.condition} ({args.trials} trials/technique, "
              f"{len(TECHNIQUES)} techniques) ===")
        print("IMPORTANT: confirm the server startup log already shows the correct "
              f"[ON]/[OFF] pattern for '{args.condition}' before continuing.")
        if args.yes:
            print("(--yes given, skipping interactive confirmation)")
        else:
            input("Press ENTER once confirmed...")

        for technique, (pattern, attack_fn, special) in TECHNIQUES.items():
            print(f"\n--- {technique} ({args.condition}) ---")
            for trial in range(1, args.trials + 1):
                pos = current_log_size(args.logfile)
                print(f"  [Trial {trial}] firing {technique}...")

                if special == "priv_pod":
                    pod_name = attack_t1548_priv_pod(trial)
                elif special == "rbac005":
                    binding_name, role_name = attack_t1548_005(trial)
                else:
                    attack_fn()

                fired, line, _, elapsed = wait_for_pattern(args.logfile, pos, pattern, DETECT_WAIT_SECONDS)
                print(f"    fired={int(fired)} (waited {elapsed:.1f}s)")
                writer.writerow([args.condition, technique, trial, int(fired), round(elapsed, 2)])
                out_f.flush()

                if special == "priv_pod":
                    cleanup_t1548_priv_pod(pod_name)
                elif special == "rbac005":
                    cleanup_t1548_005(binding_name, role_name)

                time.sleep(INTER_TRIAL_GAP.get(technique, DEFAULT_INTER_TRIAL_GAP))

        print(f"\n=== {args.condition} complete. Results appended to {args.outfile} ===")


if __name__ == "__main__":
    main()
