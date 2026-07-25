#!/usr/bin/env python3
"""
Benign-control trials for CAGE's false-positive evaluation.

REPRODUCIBILITY NOTE — read before trusting this against week4/results_benign.csv:

results_benign.csv was introduced whole-cloth in the CAGE-mine/CAGE-original
reconciliation merge, with no accompanying generation script, no incremental
commit history, and no documented commands anywhere in the repository —
only the four category names ("T1059/T1021/T1548/T1610 control", per
README.md's Evaluation section) and their aggregate results survive. This
script does NOT reproduce that exact original methodology — it cannot be
recovered from anything in this repository. It implements a new, clearly
specified benign-control methodology against the CURRENT detection code,
chosen to be the most plausible reconstruction of the documented intent —
see README.md's Evaluation section for the full writeup of this
investigation, including one inconsistency that could not be resolved.

What's reconstructable from the repo and used here:
  - The four categories (benign analogs of T1059/T1021/T1548/T1610) and a
    10-trial-per-category design, matching every other trial-based script
    in week4/ (run_ablation.py, capture_latency.py, run_t1548_trials.sh).
  - "legitimate-app" almost certainly exists specifically to be the
    "known good" pod for this purpose: it's the one pod name that matches
    causal_graph.py's SHELL_WHITELIST_POD_PREFIXES, and its whitelisting
    is otherwise unused by any attack script.
  - week4/benign-app.yaml (a "benign-worker" pod, NOT on the whitelist)
    already existed in this repo but was never referenced by any script —
    almost certainly the intended target for the T1610 traffic control,
    since legitimate-app being whitelisted would make a T1610 test against
    it structurally unable to ever fire, which contradicts the documented
    10/10-fired result for that category.

What could NOT be reconstructed or verified:
  - The exact original commands. "Benign shell use" / "benign exec" /
    "benign privileged behavior" (README's phrasing) admit many equally
    plausible literal commands; none survive anywhere in the repo.
  - Why the original T1021 control reportedly showed 0/10. Traced
    causal_graph.py's _check_t1021(): unlike _check_t1059 and
    _check_t1548_privesc, it has NO whitelist check at all — it fires on
    every single pod_exec event unconditionally. That means, against the
    code currently in this repository, there is no pod (whitelisted or
    not) a real `kubectl exec` could target and produce a 0/10 result.
    Possible explanations: the original trial never actually ran
    `kubectl exec` despite the category name, or _check_t1021 once had a
    whitelist check that was since removed, or the original number is
    stale/wrong. This script does not guess further — it runs the T1021
    trial anyway (against legitimate-app, for consistency with the other
    two whitelisted trials) and documents in its own output that a
    high/100% fire rate is the *expected*, current-code-correct outcome,
    not a regression to chase.

Usage:
    python3 week4/run_benign_controls.py <logfile> [output_csv]

<logfile> must be the CAGE server's stdout/log file (same convention as
run_ablation.py) so fired/not-fired can be determined by tailing it.
"""
import subprocess, time, sys, csv, os

TRIALS_PER_CATEGORY = int(os.environ.get("BENIGN_TRIALS", "10"))
DETECT_WAIT_SECONDS = 15  # a benign trial should NOT alert; this is how
                          # long we watch before concluding "stayed silent"

BENIGN_APP_YAML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign-app.yaml")

CATEGORIES = [
    {
        "label": "T1059_whitelisted",
        "check_pattern": "T1059",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "sh", "-c", "id"],
        "note": "legitimate-app is on SHELL_WHITELIST_POD_PREFIXES -- tests "
                "whether the whitelist suppresses an otherwise T1059-shaped "
                "shell exec. Expected: never fires.",
    },
    {
        "label": "T1021_no_whitelist_check",
        "check_pattern": "T1021",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "sh", "-c", "id"],
        "note": "_check_t1021 has NO whitelist check in the current code -- "
                "expected to fire on every trial regardless of target pod. "
                "Included to document current behavior, not to claim a "
                "0/10 result (see module docstring).",
    },
    {
        "label": "T1548_whitelisted",
        "check_pattern": "T1548",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "su", "root", "-c", "id"],
        "note": "legitimate-app is on SHELL_WHITELIST_POD_PREFIXES -- tests "
                "whether the whitelist suppresses an actual su invocation. "
                "Expected: never fires.",
    },
]


def ensure_benign_worker():
    subprocess.run(["kubectl", "apply", "-f", BENIGN_APP_YAML],
                    stdout=subprocess.DEVNULL, check=True)
    subprocess.run(["kubectl", "wait", "--for=condition=Ready", "pod/benign-worker",
                     "--timeout=60s"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def tail_new_lines(logfile, start_pos):
    with open(logfile, "r") as f:
        f.seek(start_pos)
        lines = f.readlines()
        end_pos = f.tell()
    return lines, end_pos


def wait_for_fire(logfile, pos, pattern, seconds):
    """Returns (fired: bool, end_pos: int). Mirrors run_ablation.py's
    detection-wait loop but for the OPPOSITE claim: benign trials expect
    silence, so timing out with no match is the success case."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        lines, pos = tail_new_lines(logfile, pos)
        for line in lines:
            if pattern in line and any(k in line for k in ("WARNING", "CRITICAL", "HIGH", "MEDIUM", "LOW")):
                return True, pos
        time.sleep(0.2)
    return False, pos


def get_pod_ip(pod_name):
    return subprocess.run(
        ["kubectl", "get", "pod", pod_name, "-o", "jsonpath={.status.podIP}"],
        capture_output=True, text=True
    ).stdout.strip()


def run_t1610_control(logfile, pos, trial, writer):
    """benign-worker makes ordinary connections to 2 distinct destinations
    -- well under CONNECTION_BURST_THRESHOLD=5 -- the one category with
    real discriminating logic in the current detector, so this is the
    trial that actually answers README's open item: does the burst-
    threshold fix (plus the _conn_burst staleness fix) hold up against
    ordinary, non-scan-like pod-to-pod traffic?"""
    ips = [get_pod_ip("legitimate-app")]
    scan_target_ip = subprocess.run(
        ["kubectl", "get", "pods", "-l", "app=scan-targets", "-o", "jsonpath={.items[0].status.podIP}"],
        capture_output=True, text=True
    ).stdout.strip()
    if scan_target_ip:
        ips.append(scan_target_ip)
    ips = [ip for ip in ips if ip]

    for ip in ips:
        subprocess.run(
            ["kubectl", "exec", "benign-worker", "--", "bash", "-c",
             f"exec 3<>/dev/tcp/{ip}/80; sleep 1; exec 3<&-"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        time.sleep(1)

    fired, pos = wait_for_fire(logfile, pos, "T1610", DETECT_WAIT_SECONDS)
    print(f"    fired={int(fired)}")
    writer.writerow(["benign_T1610_control", "benign", "T1610", trial, int(fired)])
    return pos


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 week4/run_benign_controls.py <logfile> [output_csv]")
        sys.exit(1)

    logfile = sys.argv[1]
    outfile = sys.argv[2] if len(sys.argv) > 2 else "week4/results_benign_v2.csv"

    if not os.path.exists(logfile):
        print(f"ERROR: log file {logfile} does not exist. Is the server running and pointed at this log?")
        sys.exit(1)

    print("Deploying benign-worker (week4/benign-app.yaml) if not already present...")
    ensure_benign_worker()

    write_header = not os.path.exists(outfile)
    with open(outfile, "a", newline="") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["scenario_name", "benign", "technique", "trial", "fire_count"])

        for cat in CATEGORIES:
            print(f"\n=== {cat['label']} ({TRIALS_PER_CATEGORY} trials) ===")
            print(f"    {cat['note']}")
            for trial in range(1, TRIALS_PER_CATEGORY + 1):
                pos = os.path.getsize(logfile)
                subprocess.run(cat["cmd"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                fired, _ = wait_for_fire(logfile, pos, cat["check_pattern"], DETECT_WAIT_SECONDS)
                print(f"  [Trial {trial}] fired={int(fired)}")
                writer.writerow([f"benign_{cat['label']}_control", "benign",
                                  cat["check_pattern"], trial, int(fired)])
                f.flush()
                time.sleep(1)

        print(f"\n=== T1610_benign (sub-threshold traffic, {TRIALS_PER_CATEGORY} trials) ===")
        print("    benign-worker -> 2 ordinary destinations, well under the "
              "5-distinct-destination/10s burst threshold. Expected: never fires.")
        pos = os.path.getsize(logfile)
        for trial in range(1, TRIALS_PER_CATEGORY + 1):
            pos = run_t1610_control(logfile, pos, trial, writer)
            f.flush()
            time.sleep(3)

    print(f"\nDone. Results written to {outfile}")
    print("(week4/results_benign.csv is left untouched -- it predates the "
          "T1610 burst-threshold fix and is kept as historical data; see "
          "README.md.)")


if __name__ == "__main__":
    main()
