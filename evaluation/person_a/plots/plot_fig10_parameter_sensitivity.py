#!/usr/bin/env python3
"""
Fig. 10 -- two-panel: (a) precision-recall style curve across the T1610
burst-threshold sweep, (b) evasion-boundary outcomes (just-under vs.
at-threshold) for T1610/T1499/T1613 at their DEFAULT thresholds, from
results_parameter_sensitivity.csv (E7 + E9 merged -- see
EVALUATION_REVIEW.md Gap 2).

Usage:
    python3 evaluation/person_a/plots/plot_fig10_parameter_sensitivity.py \\
        <results_parameter_sensitivity.csv> <output_dir>
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import apply_style, save_figure, PALETTE  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402

DEFAULT_THRESHOLDS = {"T1610": 5, "T1499": 25, "T1613": 10}


def load_rows(csv_path):
    return list(csv.DictReader(open(csv_path)))


def plot_panel_a(ax, rows):
    """Sweep mode: for the swept technique, plot recall (attack trials) vs.
    threshold value. This script expects sweep rows to include BOTH an
    attack-intensity condition and a benign condition distinguished by
    context outside this CSV (see README.md) -- if only attack data is
    present, this panel shows recall only, labeled accordingly."""
    sweep_rows = [r for r in rows if r["mode"] == "sweep"]
    by_threshold = defaultdict(lambda: [0, 0])
    for r in sweep_rows:
        t = int(r["independent_var"])
        by_threshold[t][1] += 1
        if r["fired"] in ("1", "True", "true"):
            by_threshold[t][0] += 1

    thresholds = sorted(by_threshold.keys())
    recalls = [by_threshold[t][0] / by_threshold[t][1] * 100 if by_threshold[t][1] else 0
               for t in thresholds]

    ax.plot(thresholds, recalls, marker="o", color=PALETTE["fused"], linewidth=1.5)
    if 5 in thresholds:
        idx = thresholds.index(5)
        ax.scatter([5], [recalls[idx]], color=PALETTE["attack"], s=80, zorder=5,
                    marker="*", label="Chosen operating point (5)")
    ax.set_xlabel("CONNECTION_BURST_THRESHOLD")
    ax.set_ylabel("Detection rate on fixed-size attack (%)")
    ax.set_title("(a) T1610 Threshold Sweep", fontsize=8)
    ax.set_ylim(-5, 105)
    ax.legend(fontsize=6)


def plot_panel_b(ax, rows):
    evasion_rows = [r for r in rows if r["mode"] == "evasion"]
    techniques = list(DEFAULT_THRESHOLDS.keys())
    y_positions = {}
    y = 0
    labels = []

    for tech in techniques:
        for boundary, marker_offset in [("just_under", -0.15), ("at_threshold", 0.15)]:
            matching = [r for r in evasion_rows if r["technique"] == tech and
                        r["independent_var"] == boundary]
            if not matching:
                continue
            fired = sum(1 for r in matching if r["fired"] in ("1", "True", "true"))
            total = len(matching)
            rate = fired / total * 100 if total else 0
            color = PALETTE["attack"] if boundary == "just_under" else PALETTE["fused"]
            # Read the actual attack_intensity used from the data rather
            # than assuming threshold-1 -- T1499's just_under uses a
            # comfortable margin (n=15), not exactly threshold-1=24 (see
            # PAPER_DRAFT.md's Limitations for why). Verified live: the
            # old hardcoded-assumption version mislabeled this point.
            actual_n = matching[0]["attack_intensity"]
            label = f"{tech} (n={actual_n})"
            ax.scatter([rate], [y + marker_offset], color=color, s=60, zorder=3,
                        edgecolors="black", linewidths=0.5)
            ax.text(rate + 3, y + marker_offset, label, fontsize=5.5, va="center")
        y_positions[tech] = y
        labels.append(tech)
        y += 1

    ax.set_yticks(list(y_positions.values()))
    ax.set_yticklabels(labels)
    ax.set_xlabel("Fired rate (%)")
    ax.set_xlim(-5, 130)
    ax.set_title("(b) Evasion Boundary at Default Thresholds", fontsize=8)
    ax.scatter([], [], color=PALETTE["attack"], label="Just under threshold")
    ax.scatter([], [], color=PALETTE["fused"], label="At threshold")
    ax.legend(fontsize=6, loc="lower right")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("output_dir")
    args = ap.parse_args()

    rows = load_rows(args.csv_path)
    apply_style()

    has_sweep = any(r["mode"] == "sweep" for r in rows)
    has_evasion = any(r["mode"] == "evasion" for r in rows)

    # Single-panel when only one mode's data is present (E7 sweep was
    # explicitly descoped for this evaluation cycle -- see
    # EVALUATION_REVIEW.md/PAPER_DRAFT.md's Limitations) -- a shipped
    # figure with an empty "no data yet" placeholder panel is not
    # submission-quality. Two-panel layout is used automatically once
    # sweep data exists.
    if has_sweep and has_evasion:
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(7.0, 3.0))
        plot_panel_a(ax1, rows)
        plot_panel_b(ax2, rows)
        fig.suptitle("Parameter Sensitivity & Evasion Boundary", fontsize=9, y=1.03)
    elif has_evasion:
        fig, ax2 = plt.subplots(1, 1, figsize=(3.4, 3.0))
        plot_panel_b(ax2, rows)
        ax2.set_title("")
        fig.suptitle("Evasion Boundary at Default Thresholds", fontsize=9, y=1.02)
    else:
        fig, ax1 = plt.subplots(1, 1, figsize=(3.4, 3.0))
        plot_panel_a(ax1, rows)
        ax1.set_title("")
        fig.suptitle("T1610 Threshold Sweep", fontsize=9, y=1.02)

    fig.tight_layout()
    pdf, png = save_figure(fig, args.output_dir, "fig10_parameter_sensitivity")
    print(f"Fig. 10 -> {pdf}")


if __name__ == "__main__":
    main()
