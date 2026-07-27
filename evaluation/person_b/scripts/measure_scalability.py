#!/usr/bin/env python3
"""
E6 — NetworkMonitor sequential-polling cycle time vs. number of monitored
pods.

NetworkMonitor.start() snapshots the pod-UID cache ONCE, at server startup,
to build its list of monitored pods (src/network_monitor.py) -- it does not
re-discover pods added/removed while already running. So testing different
N requires restarting the server after each scaling step, not just scaling
scan-targets live.

For each N in --counts, this script:
  1. `kubectl scale deployment scan-targets --replicas=N`, waits for Ready.
  2. Restarts the CAGE server (fresh log file per N).
  3. Watches the log for repeated "waves" of NetworkMonitor's own polling
     activity (`[QUEUED] .../bin/cat` process_exec events -- each poll
     cycle execs `cat /proc/net/tcp` once per monitored pod, so a cluster
     of these lines close together in time marks one sweep).
  4. Records the gap between consecutive wave start times as one cycle-time
     sample, averaged over --waves-per-n sweeps.

Usage:
  python3 measure_scalability.py --counts 1,2,4,8,16 --waves-per-n 3
"""
import argparse
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
WAVE_GROUPING_SEC = 1.5   # cat-execs within this many seconds of each other count as the same sweep
NOMINAL_POLL_INTERVAL_SEC = 5


def restart_server(repo_dir, logfile):
    # subprocess.run(capture_output=True) here (as opposed to Popen) hung
    # indefinitely in live testing: `cmd & disown` inside a `bash -c`
    # backgrounds python3 src/server.py, but subprocess.run still has to
    # read stdout/stderr to EOF before returning, and that pipe doesn't
    # reliably close once a detached grandchild process exists on this
    # setup -- run_latency_batch.py's start_server already worked around
    # this the same way (Popen + .wait() on the quick bash -c wrapper
    # only, never capturing output from a command that backgrounds a
    # long-lived process).
    subprocess.run(["bash", "-c", 'pkill -9 -f "src/server.py"; sleep 2'], timeout=15)
    # stdin=DEVNULL: without it this wrapper inherits this script's own
    # stdin, which on a nohup'd/backgrounded parent can leave the `bash -c`
    # wrapper itself hanging around indefinitely even after `disown` --
    # caught live during a full-scale E8 run, where a leftover wrapper from
    # an earlier E6 restart made `pgrep -f "src/server.py" | head -1` (used
    # by run_full_scale_all.sh's get_server_log()) resolve to the wrapper's
    # own fd instead of the real server's, silently pointing E8's detection
    # checks at the wrong log file for an entire run.
    p = subprocess.Popen(["bash", "-c",
                           f'cd "{repo_dir}" && nohup python3 src/server.py > "{logfile}" 2>&1 & disown; echo started'],
                          stdin=subprocess.DEVNULL)
    p.wait(timeout=15)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        rc, out, _ = common.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://localhost:5000/"])
        if out.strip() == "200":
            return True
        time.sleep(1)
    return False


def observe_cycle_times(logfile, n_waves, timeout_sec):
    """Watch logfile for `n_waves` distinct sweeps of `bin/cat` process_exec
    entries and return the list of gaps (seconds) between consecutive wave
    start times."""
    pattern = re.compile(r"^(\S+ \S+) INFO \[QUEUED\].*bin/cat")
    wave_starts = []
    pos = os.path.getsize(logfile)
    deadline = time.monotonic() + timeout_sec
    last_ts = None
    while time.monotonic() < deadline and len(wave_starts) < n_waves:
        lines, pos = common.tail_new_lines(logfile, pos)
        for line in lines:
            m = pattern.match(line)
            if not m:
                continue
            ts = common.parse_log_ts(line)
            if ts is None:
                continue
            if last_ts is None or (ts - last_ts).total_seconds() > WAVE_GROUPING_SEC:
                wave_starts.append(ts)
            last_ts = ts
        time.sleep(0.3)
    gaps = [(wave_starts[i + 1] - wave_starts[i]).total_seconds() for i in range(len(wave_starts) - 1)]
    return gaps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--counts", default="1,2,4,8,16")
    ap.add_argument("--waves-per-n", type=int, default=3)
    ap.add_argument("--repo", default=os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
    args = ap.parse_args()
    counts = [int(x) for x in args.counts.split(",")]

    outpath = os.path.join(DATA_DIR, "results_scalability.csv")
    f, writer = common.ensure_csv_header(
        outpath, ["n_scan_target_pods", "n_total_monitored_pods", "cycle_gap_sec", "target_interval_sec"]
    )

    for n in counts:
        print(f"[scalability] scaling scan-targets to {n} replicas...")
        common.run(["kubectl", "scale", "deployment", "scan-targets", f"--replicas={n}"], timeout=30)
        common.run(["kubectl", "wait", "--for=condition=Ready", "pod", "-l", "app=scan-targets", "--timeout=90s"], timeout=100)

        logfile = os.path.join(args.repo, f"evaluation_e6_n{n}.log")
        ok = restart_server(args.repo, logfile)
        if not ok:
            print(f"  WARNING: server did not come up cleanly for n={n}, skipping")
            continue
        time.sleep(6)  # let the initial UID-cache warmup settle before measuring

        rc, out, _ = common.run(["kubectl", "get", "pods", "--no-headers"])
        n_total = len([l for l in out.strip().split("\n") if l])

        gaps = observe_cycle_times(logfile, args.waves_per_n, timeout_sec=NOMINAL_POLL_INTERVAL_SEC * args.waves_per_n * 6 + 30)
        if not gaps:
            print(f"  WARNING: no wave data captured for n={n}")
        for gap in gaps:
            writer.writerow([n, n_total, round(gap, 2), NOMINAL_POLL_INTERVAL_SEC])
        f.flush()
        mean_gap = sum(gaps) / len(gaps) if gaps else float("nan")
        print(f"  n={n} total_pods={n_total} mean_cycle_gap={mean_gap:.2f}s (target {NOMINAL_POLL_INTERVAL_SEC}s)")

    f.close()
    print(f"[scalability] done -> {outpath}")


if __name__ == "__main__":
    main()
