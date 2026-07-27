#!/usr/bin/env python3
"""Fig. 6 — Cumulative Distribution of End-to-End Detection Latency by
Telemetry Source. Reads evaluation/person_b/data/results_latency.csv."""
import csv
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "results_latency.csv")
OUT = os.path.join(HERE, "..", "figures", "fig6_latency_cdf.png")

SOURCE_MAP = {"T1059": "Tetragon (T1059)", "T1552": "Audit log (T1552)"}


def load():
    by_technique = {}
    with open(DATA) as f:
        for row in csv.DictReader(f):
            if row["latency_sec"] in ("", None):
                continue
            by_technique.setdefault(row["technique"], []).append(float(row["latency_sec"]))
    return by_technique


def main():
    data = load()
    if not data:
        print("No latency data found — run run_latency_batch.py distribution first.")
        sys.exit(1)

    fig, ax = plt.subplots(figsize=(7, 5))
    colors = {"T1059": "#d62728", "T1552": "#1f77b4"}
    for technique, values in sorted(data.items()):
        values = np.sort(np.array(values))
        y = np.arange(1, len(values) + 1) / len(values)
        label = SOURCE_MAP.get(technique, technique)
        ax.step(values, y, where="post", label=f"{label} (n={len(values)})",
                color=colors.get(technique), linewidth=2)
        ax.scatter(values, y, color=colors.get(technique), s=15, zorder=3)

    ax.set_xlabel("Detection latency (seconds)")
    ax.set_ylabel("Fraction of trials detected within X seconds")
    ax.set_ylim(0, 1.05)
    ax.set_xlim(left=0)
    ax.set_title("Fig. 6 — CDF of End-to-End Detection Latency by Telemetry Source")
    ax.legend(loc="lower right")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fig.savefig(OUT, dpi=150)
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
