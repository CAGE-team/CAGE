#!/usr/bin/env python3
"""Fig. 9 — CAGE Resource Utilization Over Time Across Idle, Active-
Detection, and Post-Load Phases. Reads
evaluation/person_b/data/results_overhead.csv."""
import csv
import os
import sys
from datetime import datetime
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "results_overhead.csv")
OUT = os.path.join(HERE, "..", "figures", "fig11_resource_overhead.png")

PHASE_COLOR = {"idle_pre": "#888888", "active": "#d62728", "idle_post": "#1f77b4", "baseline_cage_off": "#2ca02c"}


def load():
    rows = []
    with open(DATA) as f:
        for row in csv.DictReader(f):
            if row["component"] != "server" or row["phase"] == "baseline_cage_off":
                continue
            rows.append(row)
    return rows


def main():
    rows = load()
    if not rows:
        print("No overhead data found — run measure_overhead.py first.")
        sys.exit(1)

    t0 = datetime.fromisoformat(rows[0]["timestamp"])
    times = [(datetime.fromisoformat(r["timestamp"]) - t0).total_seconds() for r in rows]
    cpu = [float(r["cpu_pct"]) for r in rows]
    rss = [float(r["rss_mb"]) for r in rows]
    phases = [r["phase"] for r in rows]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(9, 6), sharex=True)

    ax1.plot(times, cpu, color="#d62728", linewidth=1.5)
    ax1.set_ylabel("CPU (%)")
    ax1.set_title("Fig. 9 — CAGE Server Resource Utilization Over Time")
    ax1.grid(True, alpha=0.3)

    ax2.plot(times, rss, color="#1f77b4", linewidth=1.5)
    ax2.set_ylabel("RSS (MB)")
    ax2.set_xlabel("Elapsed time (seconds)")
    ax2.grid(True, alpha=0.3)

    # mark phase boundaries
    prev_phase = None
    for t, phase in zip(times, phases):
        if phase != prev_phase:
            for ax in (ax1, ax2):
                ax.axvline(t, color="black", linestyle=":", alpha=0.5)
            ax1.text(t, ax1.get_ylim()[1] * 0.95, phase, rotation=90, fontsize=8, va="top")
            prev_phase = phase

    fig.tight_layout()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fig.savefig(OUT, dpi=150)
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
