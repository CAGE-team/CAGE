#!/usr/bin/env python3
"""Builds Table 4 (latency stats), Table 5 (+5b, overhead/scalability), and
the E8 fault-recovery tables as markdown from the CSVs in
evaluation/person_b/data/.

Continuous measurements (latency, CPU/RSS, cycle time) get a t-distribution
95% CI on the mean; E8's per-fault success rate (a proportion, not a
continuous measurement) gets a Wilson score 95% CI instead. Both choices
follow EVALUATION_REVIEW.md's recommendation. No scipy dependency: the
t-critical values below are the standard two-tailed alpha=0.05 table,
looked up by degrees of freedom (ceiling-matched to the nearest tabulated
df so the reported interval is never narrower than it should be)."""
import csv
import math
import os
import statistics as stats

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
TABLES = os.path.join(HERE, "..", "tables")

# Two-tailed 95% (alpha=0.05) critical t-values, standard table.
_T_TABLE = {
    1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365,
    8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179, 13: 2.160, 14: 2.145,
    15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086,
    21: 2.080, 22: 2.074, 23: 2.069, 24: 2.064, 25: 2.060, 26: 2.056,
    27: 2.052, 28: 2.048, 29: 2.045, 30: 2.042, 40: 2.021, 60: 2.000,
    120: 1.980,
}
_Z_95 = 1.959963985


def t_crit_95(df):
    if df < 1:
        return None
    for k in sorted(_T_TABLE):
        if df <= k:
            return _T_TABLE[k]
    return _Z_95


def wilson_ci_95(successes, n):
    """Wilson score interval for a binomial proportion. Preferred over the
    naive normal-approximation interval for small n (e.g. E8's 5 reps per
    scenario), where the naive interval can go outside [0,1] or badly
    understate uncertainty."""
    if n == 0:
        return None
    p = successes / n
    z = _Z_95
    denom = 1 + z * z / n
    center = p + z * z / (2 * n)
    adj = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((center - adj) / denom, (center + adj) / denom)


def load_csv(name):
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return list(csv.DictReader(f))


def summarize(values):
    if not values:
        return None
    values = sorted(values)
    n = len(values)
    mean = stats.mean(values)
    sd = stats.stdev(values) if n > 1 else 0.0
    ci = None
    if n > 1:
        tcrit = t_crit_95(n - 1)
        margin = tcrit * sd / math.sqrt(n)
        ci = (mean - margin, mean + margin)
    return {
        "n": n,
        "min": values[0],
        "median": stats.median(values),
        "mean": mean,
        "stdev": sd,
        "ci95": ci,
        "p95": values[min(n - 1, int(round(0.95 * (n - 1))))],
        "max": values[-1],
    }


def fmt_ci(ci):
    if ci is None:
        return "—"
    return f"[{ci[0]:.2f}, {ci[1]:.2f}]"


def table4_latency():
    rows = load_csv("results_latency.csv")
    by_technique = {}
    for r in rows:
        if not r["latency_sec"]:
            continue
        by_technique.setdefault(r["technique"], []).append(float(r["latency_sec"]))

    lines = [
        "## Table 4 — Detection Latency Statistics by Technique/Source\n",
        "| Technique | Source | N | Min (s) | Median (s) | Mean (s) | 95% CI of mean (s) | Stdev (s) | p95 (s) | Max (s) |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    source_map = {"T1059": "Tetragon eBPF", "T1552": "K8s audit log"}
    for tech, values in sorted(by_technique.items()):
        s = summarize(values)
        if not s:
            continue
        lines.append(
            f"| {tech} | {source_map.get(tech, '—')} | {s['n']} | {s['min']:.2f} | {s['median']:.2f} "
            f"| {s['mean']:.2f} | {fmt_ci(s['ci95'])} | {s['stdev']:.2f} | {s['p95']:.2f} | {s['max']:.2f} |"
        )
    lines.append(
        "\n95% CI of the mean is a t-distribution interval (df = N−1); "
        "not reported when N ≤ 1."
    )
    return "\n".join(lines) + "\n"


def table5_overhead():
    rows = load_csv("results_overhead.csv")
    by_phase = {}
    for r in rows:
        if r["component"] != "server":
            continue
        by_phase.setdefault(r["phase"], {"cpu": [], "rss": []})
        by_phase[r["phase"]]["cpu"].append(float(r["cpu_pct"]))
        by_phase[r["phase"]]["rss"].append(float(r["rss_mb"]))

    lines = [
        "## Table 5 — Resource Overhead Summary (CAGE Server Process)\n",
        "| Phase | N samples | Mean CPU (%) | 95% CI CPU (%) | Peak CPU (%) | Mean RSS (MB) | 95% CI RSS (MB) | Peak RSS (MB) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    phase_order = ["baseline_cage_off", "idle_pre", "active", "idle_post"]
    for phase in phase_order:
        d = by_phase.get(phase)
        if not d or not d["cpu"]:
            if phase == "baseline_cage_off":
                lines.append("| baseline_cage_off | — | 0.0 | — | 0.0 | 0.0 | — | 0.0 |")
            continue
        cpu_s = summarize(d["cpu"])
        rss_s = summarize(d["rss"])
        lines.append(
            f"| {phase} | {len(d['cpu'])} | {cpu_s['mean']:.1f} | {fmt_ci(cpu_s['ci95'])} | {max(d['cpu']):.1f} "
            f"| {rss_s['mean']:.1f} | {fmt_ci(rss_s['ci95'])} | {max(d['rss']):.1f} |"
        )
    lines.append(
        "\n95% CI is a t-distribution interval on the mean (df = N_samples−1). "
        "Note %CPU as reported by `ps` is a decaying lifetime average, not an "
        "instantaneous reading — see the Limitations section."
    )
    return "\n".join(lines) + "\n"


def table5b_scalability():
    rows = load_csv("results_scalability.csv")
    by_n = {}
    for r in rows:
        by_n.setdefault(int(r["n_scan_target_pods"]), {"gaps": [], "total": r["n_total_monitored_pods"], "target": r["target_interval_sec"]})
        by_n[int(r["n_scan_target_pods"])]["gaps"].append(float(r["cycle_gap_sec"]))

    lines = [
        "## Table 5b — NetworkMonitor Sequential-Polling Cycle Time vs. Pod Count\n",
        "| N scan-target pods | Total monitored pods | N waves | Mean cycle time (s) | 95% CI (s) | Target interval (s) | Over target? |",
        "|---|---|---|---|---|---|---|",
    ]
    for n in sorted(by_n.keys()):
        d = by_n[n]
        if not d["gaps"]:
            continue
        s = summarize(d["gaps"])
        target = float(d["target"])
        over = "yes" if s["mean"] > target else "no"
        lines.append(
            f"| {n} | {d['total']} | {s['n']} | {s['mean']:.2f} | {fmt_ci(s['ci95'])} | {target:.0f} | {over} |"
        )
    lines.append("\n95% CI is a t-distribution interval on the mean (df = N_waves−1).")
    return "\n".join(lines) + "\n"


def table_fault_recovery():
    rows = load_csv("results_fault_recovery.csv")
    lines = [
        "## E8 — Fault Injection and Recovery, Per-Rep Detail (supporting Fig. 2)\n",
        "| Fault | Rep | Health-detected (s) | Health-recovered (s) | Functional recovery confirmed (s) | Spurious alerts during fault |",
        "|---|---|---|---|---|---|",
    ]
    for r in rows:
        lines.append(
            f"| {r['fault_type']} | {r.get('rep', '1')} | {r['t_health_detected_sec'] or '—'} | {r['t_health_recovered_sec'] or '—'} "
            f"| {r['t_functional_recovered_sec'] or '—'} | {r['alerts_during_fault'] or '0'} |"
        )
    return "\n".join(lines) + "\n"


def table_fault_recovery_summary():
    """Aggregates results_fault_recovery.csv's per-rep rows into a
    per-fault-type success rate with a Wilson 95% CI. 'Success' here means
    functional recovery was confirmed (a real attack fired after the fault
    was resolved was correctly detected) -- the strict definition, not
    merely that /api/health reported green again."""
    rows = load_csv("results_fault_recovery.csv")
    by_fault = {}
    for r in rows:
        by_fault.setdefault(r["fault_type"], {"n": 0, "success": 0, "detect": [], "recover": [], "functional": [], "spurious_total": 0})
        d = by_fault[r["fault_type"]]
        d["n"] += 1
        if r["t_functional_recovered_sec"]:
            d["success"] += 1
            d["functional"].append(float(r["t_functional_recovered_sec"]))
        if r["t_health_detected_sec"]:
            d["detect"].append(float(r["t_health_detected_sec"]))
        if r["t_health_recovered_sec"]:
            d["recover"].append(float(r["t_health_recovered_sec"]))
        if r["alerts_during_fault"]:
            try:
                d["spurious_total"] += int(r["alerts_during_fault"])
            except ValueError:
                pass

    lines = [
        "## E8 Summary — Fault-Recovery Success Rate by Scenario (Wilson 95% CI)\n",
        "| Fault | Reps (N) | Functional recovery rate | Wilson 95% CI | Mean detect (s) | Mean recover (s) | Mean functional-recovery (s) | Spurious alerts (total across reps) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for fault, d in sorted(by_fault.items()):
        rate = d["success"] / d["n"] if d["n"] else 0.0
        ci = wilson_ci_95(d["success"], d["n"])
        ci_str = f"[{ci[0]:.2f}, {ci[1]:.2f}]" if ci else "—"
        mean_detect = f"{stats.mean(d['detect']):.1f}" if d["detect"] else "—"
        mean_recover = f"{stats.mean(d['recover']):.1f}" if d["recover"] else "—"
        mean_functional = f"{stats.mean(d['functional']):.1f}" if d["functional"] else "—"
        lines.append(
            f"| {fault} | {d['n']} | {d['success']}/{d['n']} ({rate:.0%}) | {ci_str} "
            f"| {mean_detect} | {mean_recover} | {mean_functional} | {d['spurious_total']} |"
        )
    lines.append(
        "\nWilson score interval, not the naive normal-approximation interval "
        "-- appropriate for small N (this evaluation's default is 5 reps/"
        "scenario) where the naive interval can exceed [0,1] or understate "
        "uncertainty. 'Functional recovery' requires a real post-fault attack "
        "to be correctly detected, not merely /api/health reporting healthy."
    )
    return "\n".join(lines) + "\n"


def main():
    os.makedirs(TABLES, exist_ok=True)
    outputs = {
        "table4_latency.md": table4_latency(),
        "table5_overhead.md": table5_overhead(),
        "table5b_scalability.md": table5b_scalability(),
        "table_fault_recovery.md": table_fault_recovery(),
        "table_fault_recovery_summary.md": table_fault_recovery_summary(),
    }
    for name, content in outputs.items():
        path = os.path.join(TABLES, name)
        with open(path, "w") as f:
            f.write(content)
        print(f"-> {path}")


if __name__ == "__main__":
    main()
