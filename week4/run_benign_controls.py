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
specified benign-control methodology against the CURRENT detection code.

IMPORTANT — this file's own history is itself an example of why "whitelisted
pod" framing is fragile: an earlier version of this script relied on
causal_graph.py's now-removed SHELL_WHITELIST_POD_PREFIXES (a pod-name
whitelist that exempted anything named "legitimate-app*"/"debug-*" from
T1059/T1611/T1548/T1496/T1499). That mechanism was deliberately removed —
see causal_graph.py's _is_whitelisted() docstring — because a name-based
exemption is a real bypass: an attacker's own pod named "legitimate-app-evil"
would have gone undetected. Detection scope is now namespace-only
(SYSTEM_NAMESPACES, in uid_resolver.py), which "legitimate-app" was never
on (it's a regular default-namespace pod). This was verified live: a plain
`kubectl exec legitimate-app -- sh -c "id"` now fires both T1021 (always
did — no whitelist check ever existed for it) and T1059 (previously
suppressed, now correctly does not distinguish this pod from any other).

What that means for these categories:
  - T1059 / T1021 / T1548 now have NO pod-identity-based exemption at all —
    each fires unconditionally on any matching event outside a system
    namespace, full stop. There is no "benign" version of a shell exec, a
    remote exec, or an su/sudo/setcap call that this design intends to stay
    silent on — silence was never the goal; the goal was "an attacker
    cannot buy their way out of detection by naming their pod carefully."
    These three categories below are kept as *regression evidence* that
    this unconditional behavior actually holds against the current code —
    expected result is 100% fired, and that is correct, not a bug.
  - T1610 is the one rule with real behavioral discrimination (a
    5-distinct-destination/10s burst, not "any connection") independent of
    pod identity or namespace, so it remains the only category that
    measures an actual false-positive rate in the traditional sense.

Usage:
    python3 week4/run_benign_controls.py <logfile> [output_csv]

<logfile> must be the CAGE server's stdout/log file (same convention as
run_ablation.py) so fired/not-fired can be determined by tailing it.
"""
import subprocess, time, sys, csv, os

TRIALS_PER_CATEGORY = int(os.environ.get("BENIGN_TRIALS", "10"))
DETECT_WAIT_SECONDS = 60  # Live audit measurement (2026-07-25) found the
                          # kubectl-exec/tetra-getevents delivery pipe can lag
                          # up to ~28s for a single trial and appeared to grow
                          # across rapid consecutive trials -- exactly what
                          # this script runs (10 back-to-back trials per
                          # category). Too short a window here has two-sided
                          # risk: for T1059/T1021/T1548 it misreports a real
                          # detection as "stayed silent"; for T1610 it's safe
                          # either way since that category's success case is
                          # already "no match found" (see wait_for_fire).

BENIGN_APP_YAML = os.path.join(os.path.dirname(os.path.abspath(__file__)), "benign-app.yaml")

CATEGORIES = [
    {
        "label": "T1059_unconditional",
        "check_pattern": "T1059",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "sh", "-c", "id"],
        "note": "No pod-identity exemption exists for T1059 (namespace-only "
                "scope, and legitimate-app is a regular default-namespace "
                "pod). Expected: fires every trial, by design.",
    },
    {
        "label": "T1021_unconditional",
        "check_pattern": "T1021",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "sh", "-c", "id"],
        "note": "_check_t1021 has never had any exemption (namespace or "
                "pod-name) -- fires on every pod_exec event unconditionally. "
                "Expected: fires every trial, by design.",
    },
    {
        "label": "T1548_unconditional",
        "check_pattern": "T1548",
        "cmd": ["kubectl", "exec", "legitimate-app", "--", "su", "root", "-c", "id"],
        "note": "No pod-identity exemption exists for T1548 either. "
                "Expected: fires every trial, by design.",
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
