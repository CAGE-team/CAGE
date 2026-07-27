#!/usr/bin/env python3
"""
E1 (per-technique detection accuracy: TP/FP/FN/Precision/Recall/F1, with
95% Wilson confidence intervals -- Gap 1 -- and a severity breakdown --
Gap 8).

Reuses the attack functions from run_ablation_full.py rather than
duplicating attack logic. TP/FP/FN are computed directly from each
trial's own fired/not-fired result (NOT via week4.metrics.MetricsCollector's
time-window alert matching -- that matching is right for a mixed timeline
of several different concurrent attacks, but wrong for this script's
repeated-same-technique-a-few-seconds-apart pattern; verified live that it
silently misclassified benign-trial false positives as true positives for
fast-firing techniques -- see the comment in main() for the full story).

IMPORTANT, stated honestly rather than glossed over: not every technique
has a meaningful "benign near-miss" to test. Creating a privileged pod,
granting cluster-admin, or running an RBAC-discovery burst are inherently
suspicious actions at the API level -- there's no legitimate version of
"create a privileged pod" that looks different from the audit log's point
of view. For those techniques (T1496, T1548-PRIV-POD, T1548.005, T1613)
this script only runs malicious trials and reports recall, not precision --
inventing a contrived "benign" version would test nothing real. This
matches the same honesty standard already applied in
week4/run_benign_controls.py's docstring.

Usage:
    python3 evaluation/person_a/scripts/run_detection_accuracy.py \\
        <server_logfile> <output_csv> [--trials N]

Run against a `fused`-mode server (this is a headline detection-accuracy
number, not an ablation comparison).
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import time

SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
PERSON_A_DIR = os.path.dirname(SCRIPTS_DIR)
PROJECT_ROOT = os.path.dirname(os.path.dirname(PERSON_A_DIR))
sys.path.insert(0, PERSON_A_DIR)
sys.path.insert(0, PROJECT_ROOT)

from lib.wait_for_alert import wait_for_pattern, current_log_size  # noqa: E402
from lib.stats import wilson_ci, precision_recall_f1  # noqa: E402
import evaluation.person_a.scripts.run_ablation_full as attacks  # noqa: E402

DETECT_WAIT_SECONDS = 60
SEVERITY_RE = re.compile(r"\[(LOW|MEDIUM|HIGH|CRITICAL)\]")

# T1613 fires on count == RBAC_DISCOVERY_THRESHOLD exactly within a 30s
# rolling window (see run_ablation_full.py's INTER_TRIAL_GAP for the full
# explanation) -- the default 2s gap between trials leaves the previous
# trial's window still open, so trial 2+ never fires. Verified live.
DEFAULT_INTER_TRIAL_GAP = 2
INTER_TRIAL_GAP = {"T1613": 32}


def _run(cmd, timeout=15):
    # See run_ablation_full.py's _run -- a single transient timeout must
    # not crash a multi-hour N=10 run. Verified live: this exact gap
    # killed a 35-minute run with zero results saved.
    try:
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        timeout=timeout)
    except subprocess.TimeoutExpired:
        pass


def benign_t1059():
    _run('kubectl exec legitimate-app -- sh -c "id"')


def benign_t1021():
    _run('kubectl exec legitimate-app -- echo "routine-ops-check"')


def benign_t1548():
    _run('kubectl exec legitimate-app -- su root -c "id"')


def benign_t1611():
    # No exemption for T1611 either (namespace-only scope) -- same
    # "unconditional" characterization as T1059/T1021/T1548. Included for
    # completeness of the per-technique accuracy table.
    _run("kubectl exec legitimate-app -- chroot / /bin/true 2>/dev/null || true")


def benign_t1552():
    _run('kubectl exec legitimate-app -- sh -c '
         '"TOKEN=\\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null); '
         'echo have-token-\\${#TOKEN}-chars"')  # reads its OWN token file locally,
                                                  # never calls the K8s API -- should NOT
                                                  # trigger T1552 (audit-log based), a
                                                  # genuine true-negative control


def benign_t1610():
    # Sub-threshold ordinary traffic -- the one technique with real
    # behavioral discrimination (5-distinct-destination/10s burst).
    ips_raw = subprocess.run(
        ["kubectl", "get", "pod", "legitimate-app", "-o", "jsonpath={.status.podIP}"],
        capture_output=True, text=True
    ).stdout.strip()
    if ips_raw:
        _run(f'kubectl exec benign-worker -- bash -c '
             f'"exec 3<>/dev/tcp/{ips_raw}/80; sleep 1; exec 3<&-" 2>/dev/null || true')


def benign_t1499():
    # Well under FORK_BOMB_EXEC_THRESHOLD=25 -- ordinary, moderate exec volume.
    _run("kubectl exec legitimate-app -- sh -c 'for i in $(seq 1 8); do /bin/true; done'", timeout=15)


# technique -> (attack_fn_or_special, benign_fn_or_None, is_tetragon_sourced)
TECHNIQUES = {
    "T1059": (attacks.attack_t1059, benign_t1059, True),
    "T1021": (attacks.attack_t1021, benign_t1021, False),
    "T1552": (attacks.attack_t1552, benign_t1552, False),
    "T1610": (attacks.attack_t1610, benign_t1610, True),
    "T1611": (attacks.attack_t1611, benign_t1611, True),
    "T1548": (attacks.attack_t1548, benign_t1548, True),
    "T1499": (attacks.attack_t1499, benign_t1499, True),
    "T1496": (attacks.attack_t1496, None, True),          # no meaningful benign analog
    "T1613": (attacks.attack_t1613, None, False),          # no meaningful benign analog
    "T1548-PRIV-POD": ("priv_pod", None, False),            # no meaningful benign analog
    "T1548.005": ("rbac005", None, False),                  # no meaningful benign analog
}

# These two techniques' log text does NOT contain their technique code (see
# src/causal_graph.py's _check_privileged_pod_spec / _check_rbac_abuse) --
# T1548-PRIV-POD logs as "T1548: privileged pod created ..." and T1548.005
# logs as "RBAC-ABUSE: ...". The alert object's own "rule" field is correct
# in both cases; only the free-text log line omits it. Verified live:
# searching for the technique code literally always timed out (false
# negative) until this fix.
LOG_PATTERN = {
    "T1548-PRIV-POD": "privileged pod created",
    "T1548.005": "RBAC-ABUSE",
}

# T1610's benign trial needs a MORE specific pattern than the malicious
# trial does. NetworkMonitor polls continuously and re-emits "T1610:
# Network scan-like burst from attacker: ..." several times over the few
# seconds after the malicious trial (the burst condition stays true across
# multiple poll cycles) -- searching benign_t1610()'s wait window for the
# generic "T1610" substring caught one of these residual re-fires from the
# PRIOR (malicious) trial, not anything benign_t1610()'s own single
# sub-threshold connection triggered. Verified live: the false "fired=1" on
# the benign trial was a "burst from attacker" line, not "burst from
# benign-worker" -- the actual source pod benign_t1610() uses. Requiring
# the source pod name eliminates the cross-trial attribution error.
#
# Same class of bug hit T1552's benign trial: the generic "T1552" substring
# also matches chain alert text ("T1059→T1552 CHAIN on default/attacker",
# "T1021→T1059→T1552 FULL CHAIN ...") -- a chain the malicious T1552 trial
# (which runs immediately before, hitting the real secrets API on
# `attacker`) legitimately triggers by correlating with an earlier T1059
# event on the SAME pod within the 120s window. That's correct detection
# behavior, just not anything benign_t1552()'s own token-file-only read
# (against `legitimate-app`, never calling the API) triggered. Verified
# live: the false "fired=1, severity=CRITICAL" was exactly this chain
# line -- CRITICAL isn't even T1552's own severity (HIGH), which was the
# tell. The standalone T1552 alert text is unambiguous and pod-agnostic
# (benign_t1552 should never produce ANY real T1552 alert, from any pod).
BENIGN_LOG_PATTERN = {
    "T1610": "burst from benign-worker",
    "T1552": "T1552: Secret access by",
}


def fire_and_check(technique, attack_fn, logfile):
    pos = current_log_size(logfile)
    t0 = time.time()

    if attack_fn == "priv_pod":
        pod_name = attacks.attack_t1548_priv_pod(int(t0))
    elif attack_fn == "rbac005":
        binding_name, role_name = attacks.attack_t1548_005(int(t0))
    else:
        attack_fn()

    fired, line, _, elapsed = wait_for_pattern(logfile, pos, LOG_PATTERN.get(technique, technique),
                                                DETECT_WAIT_SECONDS)
    severity = None
    if fired and line:
        m = SEVERITY_RE.search(line)
        severity = m.group(1) if m else None

    if attack_fn == "priv_pod":
        attacks.cleanup_t1548_priv_pod(pod_name)
    elif attack_fn == "rbac005":
        attacks.cleanup_t1548_005(binding_name, role_name)

    return t0, fired, elapsed, severity


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile")
    ap.add_argument("outfile")
    ap.add_argument("--trials", type=int, default=15)
    args = ap.parse_args()

    if not os.path.exists(args.logfile):
        print(f"ERROR: log file {args.logfile} does not exist. Is the fused-mode server running?")
        sys.exit(1)

    # Both CSVs are opened up front and flushed after every row/technique
    # rather than accumulated in memory and written once at the end.
    # Verified live: an uncaught subprocess timeout crashed a 35-minute
    # N=10 run on technique 9 of 11 -- with the old write-once-at-the-end
    # design, that lost EVERY trial's data, not just the failed one. This
    # way a crash loses at most the technique in progress.
    detail_path = args.outfile
    summary_path = args.outfile.replace(".csv", "_summary.csv")
    detail_f = open(detail_path, "w", newline="")
    detail_w = csv.writer(detail_f)
    detail_w.writerow(["technique", "trial_type", "trial", "fired", "latency_sec", "severity"])
    detail_f.flush()

    summary_f = open(summary_path, "w", newline="")
    summary_w = csv.DictWriter(summary_f, fieldnames=[
        "technique", "tp", "fp", "fn", "precision", "recall", "f1",
        "recall_ci_low", "recall_ci_high", "has_benign_control", "source"])
    summary_w.writeheader()
    summary_f.flush()

    for technique, (attack_fn, benign_fn, is_tetragon) in TECHNIQUES.items():
        print(f"\n=== {technique} ===")
        # TP/FP/FN computed directly from each trial's OWN fired/not-fired
        # result -- deliberately NOT using week4.metrics.MetricsCollector's
        # time-window alert-to-event matching here. That matching (alerts
        # within MATCH_WINDOW_SECONDS=30 of an attack event count as a
        # detection of it) is the right tool for a mixed timeline of
        # several DIFFERENT concurrent attacks, but wrong for this script's
        # actual pattern: repeated trials of the SAME technique fired only
        # a few seconds apart. Verified live: for fast-firing techniques
        # (T1021, T1611 -- ~0s latency), a benign trial's alert landed
        # within 30s of a nearby MALICIOUS trial's attack event and got
        # counted as a true positive instead of a false positive, silently
        # inflating precision to 1.0 for techniques that are actually
        # unconditional (T1059/T1548 -- fired on both attack and benign --
        # correctly showed precision=0.5 only because their ~30s detection
        # latency happened to push matches outside the window; that was
        # luck, not correct-by-design). Each trial's fired/not-fired is
        # already ground truth on its own (wait_for_pattern is scoped to
        # only that trial's own log window), so no time-based inference is
        # needed at all.
        tp = fn_count = fp = 0

        print(f"  Malicious trials (N={args.trials}):")
        for trial in range(1, args.trials + 1):
            t0, fired, elapsed, severity = fire_and_check(technique, attack_fn, args.logfile)
            print(f"    [{trial}] fired={int(fired)} latency={elapsed:.1f}s severity={severity}")
            detail_w.writerow([technique, "attack", trial, int(fired), round(elapsed, 2), severity or ""])
            detail_f.flush()
            if fired:
                tp += 1
            else:
                fn_count += 1
            time.sleep(INTER_TRIAL_GAP.get(technique, DEFAULT_INTER_TRIAL_GAP))

        if benign_fn is not None:
            print(f"  Benign trials (N={args.trials}):")
            for trial in range(1, args.trials + 1):
                pos = current_log_size(args.logfile)
                t0 = time.time()
                benign_fn()
                benign_pattern = BENIGN_LOG_PATTERN.get(technique, LOG_PATTERN.get(technique, technique))
                fired, line, _, elapsed = wait_for_pattern(args.logfile, pos, benign_pattern,
                                                            DETECT_WAIT_SECONDS)
                severity = None
                if fired and line:
                    m = SEVERITY_RE.search(line)
                    severity = m.group(1) if m else None
                print(f"    [{trial}] fired={int(fired)} latency={elapsed:.1f}s severity={severity}")
                detail_w.writerow([technique, "benign", trial, int(fired), round(elapsed, 2), severity or ""])
                detail_f.flush()
                if fired:
                    fp += 1
                time.sleep(2)
        else:
            print("  (no meaningful benign analog for this technique -- see module docstring; "
                  "recall-only, precision not computed)")

        fn = fn_count
        precision, recall, f1 = precision_recall_f1(tp, fp, fn)
        recall_p, recall_lo, recall_hi = wilson_ci(tp, tp + fn) if (tp + fn) > 0 else (0, 0, 0)
        summary_w.writerow({
            "technique": technique, "tp": tp, "fp": fp, "fn": fn,
            "precision": round(precision, 3), "recall": round(recall, 3), "f1": round(f1, 3),
            "recall_ci_low": round(recall_lo, 3), "recall_ci_high": round(recall_hi, 3),
            "has_benign_control": benign_fn is not None,
            "source": "tetragon" if is_tetragon else "audit",
        })
        summary_f.flush()

    detail_f.close()
    summary_f.close()
    print(f"\nDone. Per-trial detail -> {detail_path}")
    print(f"      Per-technique summary (feeds Fig. 5 / Table 1) -> {summary_path}")


if __name__ == "__main__":
    main()
