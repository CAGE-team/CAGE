#!/usr/bin/env python3
"""
Fig. 6 (ablation heatmap) + Fig. 7 (MITRE tactic coverage radar), both from
results_ablation_full.csv (E2). Two figures because they answer different
questions from the same data -- Fig. 6 is the precise per-technique
numbers, Fig. 7 is the coverage *shape* across MITRE tactics. See
EVALUATION_PLAN.md E2 and EVALUATION_REVIEW.md for why both are kept.

Usage:
    python3 evaluation/person_a/plots/plot_fig3_4_ablation.py \\
        <results_ablation_full.csv> <output_dir>
"""
import argparse
import csv
import math
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import apply_style, save_figure, PALETTE  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

TECHNIQUES = ["T1059", "T1021", "T1552", "T1610", "T1611", "T1548",
              "T1496", "T1499", "T1613", "T1548-PRIV-POD", "T1548.005"]
CONDITIONS = ["tetragon_only", "audit_only", "fused"]

# MITRE tactic mapping -- grounded in causal_graph.py's own rule comments
# and README.md's technique table, not invented.
TACTIC_MAP = {
    "Execution": ["T1059"],
    "Lateral Movement": ["T1021", "T1610"],
    "Credential Access": ["T1552"],
    "Privilege Escalation": ["T1611", "T1548", "T1548-PRIV-POD", "T1548.005"],
    "Impact": ["T1496", "T1499"],
    "Discovery": ["T1613"],
}


def load_rates(csv_path):
    counts = defaultdict(lambda: defaultdict(lambda: [0, 0]))  # [fired, total]
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            cond, tech = row["condition"], row["technique"]
            counts[cond][tech][1] += 1
            if row["fired"] in ("1", "True", "true"):
                counts[cond][tech][0] += 1
    return counts


def plot_heatmap(counts, output_dir):
    apply_style()
    matrix = np.zeros((len(TECHNIQUES), len(CONDITIONS)))
    for i, tech in enumerate(TECHNIQUES):
        for j, cond in enumerate(CONDITIONS):
            fired, total = counts[cond][tech]
            matrix[i, j] = (fired / total * 100) if total > 0 else np.nan

    fig, ax = plt.subplots(figsize=(4.2, 5.0))
    im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(CONDITIONS)))
    ax.set_xticklabels(["Tetragon\nonly", "Audit log\nonly", "Fused"])
    ax.set_yticks(range(len(TECHNIQUES)))
    ax.set_yticklabels(TECHNIQUES)
    for i in range(len(TECHNIQUES)):
        for j in range(len(CONDITIONS)):
            val = matrix[i, j]
            label = "N/A" if np.isnan(val) else f"{val:.0f}"
            ax.text(j, i, label, ha="center", va="center", fontsize=6.5,
                     color="black" if (not np.isnan(val) and 20 < val < 80) else "white")
    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    cbar.set_label("Detection rate (%)")
    ax.set_title("Detection Rate by Telemetry Source and Technique")
    fig.tight_layout()
    return save_figure(fig, output_dir, "fig6_ablation_heatmap")


def plot_radar(counts, output_dir):
    apply_style()
    tactics = list(TACTIC_MAP.keys())
    n = len(tactics)
    angles = [i / n * 2 * math.pi for i in range(n)]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(4.0, 4.0), subplot_kw=dict(polar=True))
    for cond in CONDITIONS:
        values = []
        for tactic in tactics:
            techs = TACTIC_MAP[tactic]
            hit = sum(1 for t in techs if counts[cond][t][1] > 0 and
                      counts[cond][t][0] / counts[cond][t][1] > 0)
            values.append(hit / len(techs) * 100)
        values += values[:1]
        label = {"tetragon_only": "Tetragon only", "audit_only": "Audit log only",
                  "fused": "Fused"}[cond]
        ax.plot(angles, values, label=label, color=PALETTE[cond], linewidth=1.5)
        ax.fill(angles, values, color=PALETTE[cond], alpha=0.08)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(tactics, fontsize=6.5)
    ax.set_ylim(0, 100)
    ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25%", "50%", "75%", "100%"], fontsize=6)
    ax.set_title("MITRE ATT&CK Tactic Coverage by Telemetry Configuration", pad=20)
    ax.legend(loc="upper right", bbox_to_anchor=(1.35, 1.1))
    fig.tight_layout()
    return save_figure(fig, output_dir, "fig7_mitre_tactic_radar")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("output_dir")
    args = ap.parse_args()

    counts = load_rates(args.csv_path)
    pdf1, png1 = plot_heatmap(counts, args.output_dir)
    print(f"Fig. 6 (ablation heatmap) -> {pdf1}")
    pdf2, png2 = plot_radar(counts, args.output_dir)
    print(f"Fig. 7 (MITRE tactic radar) -> {pdf2}")


if __name__ == "__main__":
    main()
