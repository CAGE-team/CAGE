#!/usr/bin/env python3
"""
Fig. 5 -- per-technique Precision/Recall/F1 heatmap with 95% Wilson CIs
annotated (Gap 1), from results_detection_accuracy_summary.csv (E1).

Usage:
    python3 evaluation/person_a/plots/plot_fig5_technique_prf.py \\
        <results_detection_accuracy_summary.csv> <output_dir>
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import apply_style, save_figure  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("output_dir")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv_path)))
    techniques = [r["technique"] for r in rows]
    metrics = ["precision", "recall", "f1"]
    matrix = np.array([[float(r[m]) for m in metrics] for r in rows]) * 100

    apply_style()
    fig, ax = plt.subplots(figsize=(3.6, 5.0))
    im = ax.imshow(matrix, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels(["Precision", "Recall", "F1"])
    ax.set_yticks(range(len(techniques)))
    ax.set_yticklabels(techniques)

    for i, r in enumerate(rows):
        for j, m in enumerate(metrics):
            val = matrix[i, j]
            text = f"{val:.0f}"
            if m == "recall":
                lo, hi = float(r["recall_ci_low"]) * 100, float(r["recall_ci_high"]) * 100
                text += f"\n[{lo:.0f},{hi:.0f}]"
            ax.text(j, i, text, ha="center", va="center", fontsize=5.5,
                     color="black" if 20 < val < 80 else "white")
        if r["has_benign_control"].lower() != "true":
            ax.text(len(metrics) - 0.5, i, "*", ha="left", va="center", fontsize=9,
                     color="black", clip_on=False)

    cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.18)
    cbar.set_label("Score (%)")
    ax.set_title("Per-Technique Precision, Recall, F1\n(recall shown with 95% Wilson CI)",
                  fontsize=8)
    fig.text(0.02, -0.02, "* no benign control constructed for this technique -- "
                          "precision not meaningful (see script docstring)", fontsize=5.5)
    fig.tight_layout()
    pdf, png = save_figure(fig, args.output_dir, "fig5_technique_precision_recall_f1")
    print(f"Fig. 5 -> {pdf}")


if __name__ == "__main__":
    main()
