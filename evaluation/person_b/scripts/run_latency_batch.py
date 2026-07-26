#!/usr/bin/env python3
"""
E4 — Detection latency distribution + Tetragon connection-age sweep.

Non-interactive batch version of week4/capture_latency.py's core logic
(no input() prompts) so it can run unattended for N trials. Does not modify
week4/capture_latency.py — this is a new, separate driver.

Two subcommands:

  distribution   Fire N trials each for a Tetragon-sourced technique (T1059)
                 and an audit-sourced technique (T1552), recording per-trial
                 latency. -> evaluation/person_b/data/results_latency.csv

  connage        Restart the CAGE server fresh, then fire single T1059
                 trials at fixed elapsed times since server start (default
                 5s, 15s, 30s, 60s, 90s — see README.md's "Tetragon delivery
                 latency" finding for why these points matter: the recorded
                 finding was fast on a ~3s-old connection, ~30s-late on a
                 ~35s-old one). -> results_latency_by_connage.csv

Usage:
  python3 run_latency_batch.py distribution --trials 10
  python3 run_latency_batch.py connage --ages 5,15,30,60,90

Both subcommands assume attacker/legitimate-app pods already exist and the
CAGE repo is checked out at the path passed via --repo (default: this
script's own project root, four directories up).
"""
import argparse
import os
import sys
import time
import subprocess

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")

# technique -> (log pattern, attack command run inside the attacker pod)
ATTACKS = {
    "T1059": (
        "T1059",
        ["bash", "-c", "id && whoami"],
    ),
    "T1552": (
        "T1552",
        ["bash", "-c",
         'TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token); '
         'curl -s -k -H "Authorization: Bearer $TOKEN" '
         'https://kubernetes.default.svc/api/v1/namespaces/default/secrets'],
    ),
}


def ensure_curl(pod="attacker"):
    rc, out, _ = common.kubectl_exec(pod, ["which", "curl"])
    if rc != 0:
        print(f"[setup] installing curl in {pod}...")
        common.kubectl_exec(pod, ["bash", "-c", "apt-get update -qq && apt-get install -y -qq curl"], timeout=60)


def find_server_log():
    """The running server's stdout/stderr redirect target. Falls back to
    prompting the operator if it can't be inferred (the server may have
    been started with any filename in this project's convention)."""
    candidates = subprocess.run(
        ["bash", "-c", "ls -t /mnt/c/Users/*/OneDrive/Dokumen/Desktop/*/*/CAGE/*.log 2>/dev/null | head -1"],
        capture_output=True, text=True
    ).stdout.strip()
    return candidates or None


def run_distribution(args):
    logfile = args.logfile or find_server_log()
    if not logfile or not os.path.exists(logfile):
        print("ERROR: could not find the running server's log file. Pass --logfile explicitly.")
        sys.exit(1)
    print(f"[distribution] using log: {logfile}")

    outpath = os.path.join(DATA_DIR, "results_latency.csv")
    f, writer = common.ensure_csv_header(
        outpath, ["person", "technique", "trial", "t0_iso", "t1_iso", "latency_sec", "matched_line"]
    )

    ensure_curl()

    for technique, (pattern, cmd) in ATTACKS.items():
        for trial in range(1, args.trials + 1):
            pos = os.path.getsize(logfile)
            t0 = time.monotonic()
            t0_iso = common.now_iso()
            common.kubectl_exec("attacker", cmd, timeout=15)
            found, matched, ts, _ = common.wait_for_pattern(logfile, pos, pattern, args.timeout)
            if found:
                latency = round(time.monotonic() - t0, 3)
                print(f"  [{technique} trial {trial}/{args.trials}] latency={latency}s")
                writer.writerow(["personB", technique, trial, t0_iso, common.now_iso(), latency, matched])
            else:
                print(f"  [{technique} trial {trial}/{args.trials}] TIMEOUT after {args.timeout}s — not recorded as a latency sample")
                writer.writerow(["personB", technique, trial, t0_iso, "", "", "TIMEOUT"])
            f.flush()
            time.sleep(2)
    f.close()
    print(f"[distribution] done -> {outpath}")


def start_server(repo_dir, logfile):
    subprocess.run(["bash", "-c", f'pkill -9 -f "src/server.py"; sleep 2'])
    proc = subprocess.Popen(
        ["bash", "-c", f'cd "{repo_dir}" && nohup python3 src/server.py > "{logfile}" 2>&1 & disown; echo started'],
    )
    proc.wait()
    # wait for the server to actually bind before returning
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        rc, out, _ = common.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:5000/"])
        if out.strip() == "200":
            return True
        time.sleep(1)
    return False


def run_connage(args):
    repo_dir = args.repo
    logfile = os.path.join(repo_dir, "evaluation_e4_connage.log")
    ages = [int(x) for x in args.ages.split(",")]

    print(f"[connage] restarting server fresh, log -> {logfile}")
    t_server_start = time.monotonic()
    ok = start_server(repo_dir, logfile)
    if not ok:
        print("ERROR: server did not come up cleanly (port may still be held by an old process).")
        sys.exit(1)
    print("[connage] server up, waiting for warmup...")
    time.sleep(5)

    outpath = os.path.join(DATA_DIR, "results_latency_by_connage.csv")
    f, writer = common.ensure_csv_header(
        outpath, ["connection_age_target_sec", "connection_age_actual_sec", "trial", "latency_sec", "source"]
    )

    for age in ages:
        elapsed = time.monotonic() - t_server_start
        wait = age - elapsed
        if wait > 0:
            print(f"[connage] waiting {wait:.1f}s to reach target age {age}s...")
            time.sleep(wait)
        actual_age = round(time.monotonic() - t_server_start, 2)
        pos = os.path.getsize(logfile)
        t0 = time.monotonic()
        common.kubectl_exec("attacker", ["bash", "-c", "id && whoami"], timeout=15)
        found, matched, ts, _ = common.wait_for_pattern(logfile, pos, "T1059", 60)
        latency = round(time.monotonic() - t0, 3) if found else ""
        print(f"[connage] target_age={age}s actual_age={actual_age}s latency={latency}")
        writer.writerow([age, actual_age, 1, latency, "tetragon"])
        f.flush()
    f.close()
    print(f"[connage] done -> {outpath}")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)

    pd = sub.add_parser("distribution")
    pd.add_argument("--trials", type=int, default=10, help="trials per technique (plan spec: 20)")
    pd.add_argument("--timeout", type=int, default=60, help="per-trial detection wait window (seconds)")
    pd.add_argument("--logfile", default=None, help="path to the running server's log; auto-detected if omitted")

    pc = sub.add_parser("connage")
    pc.add_argument("--ages", default="5,15,30,60,90", help="comma-separated target elapsed-seconds points")
    pc.add_argument("--repo", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")),
                     help="CAGE project root")

    args = p.parse_args()
    if args.cmd == "distribution":
        run_distribution(args)
    else:
        run_connage(args)
