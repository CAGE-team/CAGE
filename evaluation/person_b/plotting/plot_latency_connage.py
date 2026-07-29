#!/usr/bin/env python3
"""Fig. 7 — Detection Latency as a Function of Tetragon Stream Connection
Age. Reads evaluation/person_b/data/results_latency_by_connage.csv."""
import csv
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "results_latency_by_connage.csv")
OUT = os.path.join(HERE, "..", "figures", "fig10_latency_vs_connage.png")


def load():
    ages, latencies = [], []
    with open(DATA) as f:
        for row in csv.DictReader(f):
            if row["latency_sec"] in ("", None):
                continue
            ages.append(float(row["connection_age_actual_sec"]))
            latencies.append(float(row["latency_sec"]))
    return np.array(ages), np.array(latencies)


def main():
    ages, latencies = load()
    if len(ages) == 0:
        print("No connection-age data found — run run_latency_batch.py connage first.")
        sys.exit(1)

    fig, ax = plt.subplots(figsize=(7, 5))
    ax.scatter(ages, latencies, color="#d62728", s=60, zorder=3, label="Observed trial")

    if len(ages) >= 2:
        coeffs = np.polyfit(ages, latencies, 1)
        trend_x = np.linspace(0, ages.max() * 1.05, 100)
        trend_y = np.polyval(coeffs, trend_x)
        ax.plot(trend_x, trend_y, "--", color="#444444", linewidth=1.5,
                label=f"Linear trend (slope={coeffs[0]:.2f}s/s)")

    for x, y in zip(ages, latencies):
        ax.annotate(f"{y:.1f}s", (x, y), textcoords="offset points", xytext=(6, 4), fontsize=8)

    ax.set_xlabel("Tetragon stream connection age at fire time (seconds)")
    ax.set_ylabel("Detection latency (seconds)")
    ax.set_title("Fig. 7 — Detection Latency vs. Tetragon Stream Connection Age")
    ax.legend(loc="upper left")
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    fig.savefig(OUT, dpi=150)
    fig.savefig(OUT.replace(".png", ".pdf"), bbox_inches="tight")
    print(f"-> {OUT}")


if __name__ == "__main__":
    main()
