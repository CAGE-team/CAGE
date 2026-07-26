#!/usr/bin/env python3
"""
E8 — Fault injection and recovery.

Three scenarios, run sequentially against a live `fused`-mode server:

  1. control-plane   `docker stop`/`start` cage-control-plane (apiserver +
                      that node's own Tetragon agent + the audit log file
                      all become unreachable at once -- the most severe of
                      the three).
  2. tetragon-kill    `kill -9` the local `kubectl exec ... tetra getevents`
                      subprocess externally (tetragon_consumer.py's own
                      reconnect-in-2s loop should self-heal with no action
                      from this script).
  3. audit-truncate   Truncate audit.log to 0 bytes in place inside the
                      control-plane container (tests tail -F's truncation
                      handling -- a different failure mode than the
                      rename-based rotation bug fixed earlier this project).

For each: records t_injected, t_health_detected (via /api/health's
enabled/stale/process_alive fields), t_recovered_health, and
t_recovered_functional (next real attack fired post-recovery that's
correctly detected -- proves the system works again, not just that
/api/health looks green). Also records alerts_during_fault: any NEW alert
that appears during the fault window despite no genuine attack command
being issued in that window -- a fault should not itself look like an
attack.

Disruptive step: scenario 1 stops a running cluster node container. It is
reversed within the same run (docker start) and functional recovery is
explicitly verified with a real attack before moving on. Run this only
against a disposable local dev cluster, never anything shared.

Usage:
  python3 inject_faults.py --scenario all
  python3 inject_faults.py --scenario control-plane
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data")
STALE_AFTER_SECONDS = 90  # src/server.py's own configured threshold


def get_alert_count():
    try:
        return len(common.http_get_json("/api/alerts"))
    except Exception:
        return None


def get_health():
    try:
        return common.http_get_json("/api/health")
    except Exception:
        return None


def poll_until(predicate, timeout_sec, interval=0.5):
    """interval defaults to 0.5s, not something coarser like 3s: the
    tetragon-consumer-kill scenario's self-healing reconnect (2s delay,
    see tetragon_consumer.py's _consume_loop) is faster than a 3s poll
    interval can reliably observe. Caught this live -- a first version of
    this script with interval=3 recorded a fault as "never detected" and
    then "recovered" after the full 120s detection timeout expired, when
    what had actually happened was sub-3-second self-healing the coarse
    polling simply never sampled during. /api/health is cheap enough that
    polling twice a second for a two-minute window costs nothing real."""
    deadline = time.monotonic() + timeout_sec
    while time.monotonic() < deadline:
        h = get_health()
        if h and predicate(h):
            return True, time.monotonic()
        time.sleep(interval)
    return False, None


def fire_and_confirm_detection(logfile, timeout=60):
    """Fires a real T1059 attack and confirms it's detected -- the
    functional-recovery check, distinct from /api/health merely looking
    healthy."""
    pos = os.path.getsize(logfile) if os.path.exists(logfile) else 0
    common.kubectl_exec("attacker", ["bash", "-c", "id && whoami"], timeout=15)
    found, matched, ts, _ = common.wait_for_pattern(logfile, pos, "T1059", timeout)
    return found


def run_scenario(name, writer, f, logfile, inject_fn, restore_fn, health_ok_predicate, self_heals=False, rep=1):
    print(f"\n=== E8 scenario: {name} (rep {rep}) ===")
    alerts_before = get_alert_count()
    t_injected = time.monotonic()
    t_injected_iso = common.now_iso()

    print(f"[{name}] injecting fault...")
    inject_fn()

    print(f"[{name}] polling /api/health for detection...")
    detected, t_detect_mono = poll_until(lambda h: not health_ok_predicate(h), STALE_AFTER_SECONDS + 30)
    t_detect_sec = round(t_detect_mono - t_injected, 1) if detected else None
    print(f"[{name}] health-detected fault: {detected} (t={t_detect_sec}s)")

    alerts_during = get_alert_count()
    spurious = None
    if alerts_before is not None and alerts_during is not None:
        spurious = max(0, alerts_during - alerts_before)

    if not self_heals:
        print(f"[{name}] restoring...")
        restore_fn()
    else:
        print(f"[{name}] no restore action needed (self-healing reconnect loop)")

    print(f"[{name}] polling /api/health for recovery...")
    recovered, t_recover_mono = poll_until(health_ok_predicate, 150)
    t_recover_sec = round(t_recover_mono - t_injected, 1) if recovered else None
    print(f"[{name}] health-recovered: {recovered} (t={t_recover_sec}s)")

    print(f"[{name}] firing a real attack to confirm functional recovery...")
    time.sleep(3)
    functional_ok = fire_and_confirm_detection(logfile)
    t_functional_sec = round(time.monotonic() - t_injected, 1) if functional_ok else None
    print(f"[{name}] functional recovery confirmed: {functional_ok}")

    alerts_after = get_alert_count()
    fault_only_spurious = spurious if spurious is not None else ""

    writer.writerow([
        name, rep, t_injected_iso, t_detect_sec, t_recover_sec, t_functional_sec,
        fault_only_spurious, alerts_before, alerts_during, alerts_after,
    ])
    f.flush()


def scenario_control_plane(writer, f, logfile, rep=1):
    def inject():
        common.run(["docker", "stop", "cage-control-plane"], timeout=60)

    def restore():
        common.run(["docker", "start", "cage-control-plane"], timeout=60)
        # give the control plane a real chance to come back before we start
        # polling /api/health for recovery -- kube-apiserver itself needs
        # tens of seconds after container start.
        time.sleep(30)

    def health_ok(h):
        # "ok" here = both consumers report enabled and not stale; process
        # liveness may briefly read False right after a restart even once
        # the API is reachable again, so it's not part of this predicate.
        try:
            return (not h["sources"]["tetragon"]["stale"]) and (not h["sources"]["audit"]["stale"])
        except Exception:
            return False

    run_scenario("control-plane-outage", writer, f, logfile, inject, restore, health_ok, self_heals=False, rep=rep)


def scenario_tetragon_kill(writer, f, logfile, rep=1):
    def inject():
        rc, out, _ = common.run(["pgrep", "-f", "tetra getevents"])
        pids = [p for p in out.strip().split("\n") if p]
        for pid in pids:
            common.run(["kill", "-9", pid])
        print(f"  killed local subprocess pid(s): {pids}")

    def restore():
        pass  # self-healing

    def health_ok(h):
        try:
            return h["sources"]["tetragon"]["process_alive"] is True and not h["sources"]["tetragon"]["stale"]
        except Exception:
            return False

    run_scenario("tetragon-consumer-kill", writer, f, logfile, inject, restore, health_ok, self_heals=True, rep=rep)


def scenario_audit_truncate(writer, f, logfile, rep=1):
    def inject():
        common.run(["docker", "exec", "cage-control-plane", "truncate", "-s", "0", "/var/log/kubernetes/audit.log"], timeout=15)

    def restore():
        pass  # tail -F --retry is expected to self-heal on truncation too

    def health_ok(h):
        try:
            return not h["sources"]["audit"]["stale"]
        except Exception:
            return False

    run_scenario("audit-log-truncate", writer, f, logfile, inject, restore, health_ok, self_heals=True, rep=rep)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="all", choices=["all", "control-plane", "tetragon-kill", "audit-truncate"])
    ap.add_argument("--logfile", required=True, help="path to the currently-running server's log file")
    ap.add_argument("--reps", type=int, default=1, help="repetitions per scenario (plan/pilot default: 1; use 5+ for a real success-rate + CI)")
    ap.add_argument("--settle-sec", type=int, default=20, help="pause between reps so the system is demonstrably quiescent before the next fault")
    args = ap.parse_args()

    outpath = os.path.join(DATA_DIR, "results_fault_recovery.csv")
    f, writer = common.ensure_csv_header(
        outpath,
        ["fault_type", "rep", "t_injected_iso", "t_health_detected_sec", "t_health_recovered_sec",
         "t_functional_recovered_sec", "alerts_during_fault", "alerts_before", "alerts_during", "alerts_after"]
    )

    scenarios = {
        "tetragon-kill": scenario_tetragon_kill,
        "audit-truncate": scenario_audit_truncate,
        "control-plane": scenario_control_plane,
    }
    order = ["tetragon-kill", "audit-truncate", "control-plane"] if args.scenario == "all" else [args.scenario]
    for s in order:
        for r in range(1, args.reps + 1):
            scenarios[s](writer, f, args.logfile, rep=r)
            if not (s == order[-1] and r == args.reps):
                print(f"[settle] pausing {args.settle_sec}s before next fault...")
                time.sleep(args.settle_sec)

    f.close()
    print(f"\n[inject_faults] done -> {outpath}")
