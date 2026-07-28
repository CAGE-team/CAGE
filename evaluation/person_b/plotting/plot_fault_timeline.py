#!/usr/bin/env python3
"""Fig. 2 — System Recovery Timeline Under Injected Infrastructure
Failures. Gantt-style, one swimlane per fault scenario. Reads
evaluation/person_b/data/results_fault_recovery.csv."""
import csv
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "results_fault_recovery.csv")
OUT = os.path.join(HERE, "..", "figures", "fig13_fault_recovery_timeline.png")

LABELS = {
    "tetragon-consumer-kill": "Tetragon consumer\nsubprocess killed",
    "audit-log-truncate": "Audit log\ntruncated",
    "control-plane-outage": "Control-plane\ncontainer stopped",
}


def load():
    rows = []
    with open(DATA) as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def main():
    rows = load()
    if not rows:
        print("No fault-recovery data found — run inject_faults.py first.")
        sys.exit(1)

    fig, ax = plt.subplots(figsize=(9, 1.2 * len(rows) + 1))
    for i, row in enumerate(rows):
        y = len(rows) - i
        label = LABELS.get(row["fault_type"], row["fault_type"])

        t_detect = float(row["t_health_detected_sec"]) if row["t_health_detected_sec"] else None
        t_recover = float(row["t_health_recovered_sec"]) if row["t_health_recovered_sec"] else None
        t_func = float(row["t_functional_recovered_sec"]) if row["t_functional_recovered_sec"] else None
        t_end = max(v for v in (t_detect, t_recover, t_func, 1) if v is not None)

        # phase bars
        ax.barh(y, (t_detect or t_end), left=0, height=0.5, color="#d62728", alpha=0.7, label="Fault active (undetected)" if i == 0 else None)
        if t_detect is not None and t_recover is not None:
            ax.barh(y, t_recover - t_detect, left=t_detect, height=0.5, color="#ff7f0e", alpha=0.7, label="Detected, recovering" if i == 0 else None)
        if t_recover is not None and t_func is not None and t_func > t_recover:
            ax.barh(y, t_func - t_recover, left=t_recover, height=0.5, color="#2ca02c", alpha=0.7, label="Health OK, confirming detection" if i == 0 else None)

        for t, marker_label in ((t_detect, "detected"), (t_recover, "health OK"), (t_func, "attack re-detected")):
            if t is not None:
                ax.plot(t, y, "|", color="black", markersize=14, markeredgewidth=1.5)
                ax.annotate(f"{marker_label}\n{t:.0f}s", (t, y), textcoords="offset points",
                            xytext=(0, 10), fontsize=7, ha="center")

        spurious = row.get("alerts_during_fault", "")
        ax.text(-2, y, f"{label}\n(spurious alerts: {spurious})", fontsize=8, ha="right", va="center")

    ax.set_yticks([])
    ax.set_xlabel("Time since fault injected (seconds)")
    ax.set_title("Fig. 2 — System Recovery Timeline Under Injected Infrastructure Failures")
    ax.set_xlim(left=-max(30, ax.get_xlim()[1] * 0.15))
    handles, labels_ = ax.get_legend_handles_labels()
    if handles:
        ax.legend(loc="lower right", fontsize=8)
    fig.tight_layout()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fig.savefig(OUT, dpi=150)
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
