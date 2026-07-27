#!/usr/bin/env python3
"""
E5 — Resource overhead of the CAGE server process across idle / active /
post-load phases, plus a trivial CAGE-off baseline.

Measures the CAGE server process itself (Flask + correlator + all three
consumer threads) via `ps -o %cpu=,rss= -p <pid>` sampled every
--interval seconds. Full plan spec is 5 min idle / 10 min active / 5 min
idle; default here is reduced for session time — see README note in
evaluation/person_b/RESULTS.md for why, and pass --idle-sec/--active-sec
to run the full-scale version later.

Scope note (documented, not silently dropped): the plan also mentions
`docker stats` for "the Tetragon container" as an alternative measurement
target. In this kind-based cluster, individual pod containers run inside
containerd *within* each kind node container — they are not separately
visible to the host's own `docker stats`, only the whole node's aggregate
figure is. Measuring the Tetragon pod's own resource use specifically
would need `kubectl top pod` (metrics-server) or an in-cluster cgroup
read, neither of which is set up in this cluster. This script measures
CAGE's own server process only, which is what the paper's overhead claim
is actually about (CAGE's cost, not Tetragon's own baseline cost).

During the active phase, generates real load with a repeating mix of
attack commands (not a full simulate_full_suite.sh run, which takes
several minutes itself due to built-in settling sleeps — a tighter
repeating loop gives more samples per unit of session time while still
exercising every consumer: Tetragon process_exec, audit-log pod/exec and
secret-access, and NetworkMonitor's own polling, which runs continuously
regardless).

Usage:
  python3 measure_overhead.py --idle-sec 60 --active-sec 120 --interval 5
"""
import argparse
import os
import sys
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")


def sample_loop(writer, f, phase_getter, interval, stop_event):
    pids = common.find_server_pid()
    if not pids:
        print("ERROR: no running `src/server.py` process found.")
        sys.exit(1)
    pid = pids[0]
    while not stop_event.is_set():
        cpu, rss = common.process_cpu_rss(pid)
        phase = phase_getter()
        if cpu is not None:
            writer.writerow([common.now_iso(), phase, "server", cpu, round(rss, 1)])
            f.flush()
        time.sleep(interval)


def active_load_loop(stop_event):
    """Fire a light, repeating mix of attack-shaped commands so all three
    consumers (Tetragon, audit log, NetworkMonitor's continuous polling)
    see real activity during the active phase."""
    common.kubectl_exec("attacker", ["bash", "-c", "which curl || (apt-get update -qq && apt-get install -y -qq curl)"], timeout=60)
    i = 0
    while not stop_event.is_set():
        i += 1
        if i % 3 == 0:
            common.kubectl_exec("attacker", [
                "bash", "-c",
                'TOKEN=$(cat /run/secrets/kubernetes.io/serviceaccount/token); '
                'curl -s -k -H "Authorization: Bearer $TOKEN" '
                'https://kubernetes.default.svc/api/v1/namespaces/default/secrets'
            ], timeout=15)
        else:
            common.kubectl_exec("attacker", ["bash", "-c", "id && whoami"], timeout=15)
        time.sleep(3)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--idle-sec", type=int, default=60, help="idle_pre and idle_post duration each (plan spec: 300)")
    ap.add_argument("--active-sec", type=int, default=120, help="active phase duration (plan spec: 600)")
    ap.add_argument("--interval", type=int, default=5, help="sampling interval seconds")
    args = ap.parse_args()

    outpath = os.path.join(DATA_DIR, "results_overhead.csv")
    f, writer = common.ensure_csv_header(outpath, ["timestamp", "phase", "component", "cpu_pct", "rss_mb"])

    # Baseline row: CAGE server process doesn't exist in this state by
    # definition, so its cost is trivially zero -- recorded explicitly
    # rather than omitted, so the table has an actual "CAGE OFF" data point.
    writer.writerow([common.now_iso(), "baseline_cage_off", "server", 0.0, 0.0])
    f.flush()

    phase = {"current": "idle_pre"}
    stop_event = threading.Event()
    sampler = threading.Thread(target=sample_loop, args=(writer, f, lambda: phase["current"], args.interval, stop_event))
    sampler.start()

    print(f"[overhead] idle_pre for {args.idle_sec}s...")
    time.sleep(args.idle_sec)

    print(f"[overhead] active for {args.active_sec}s...")
    phase["current"] = "active"
    load_stop = threading.Event()
    loader = threading.Thread(target=active_load_loop, args=(load_stop,))
    loader.start()
    time.sleep(args.active_sec)
    load_stop.set()
    loader.join(timeout=5)

    print(f"[overhead] idle_post for {args.idle_sec}s...")
    phase["current"] = "idle_post"
    time.sleep(args.idle_sec)

    stop_event.set()
    sampler.join(timeout=5)
    f.close()
    print(f"[overhead] done -> {outpath}")


if __name__ == "__main__":
    main()
