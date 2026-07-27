#!/usr/bin/env python3
"""
Fig. 8 -- cumulative chain detections vs. trial number, old (permanent
dedup) vs. new (episode-scoped dedup) code, from results_chain_dedup.csv
(E3). One panel per chain type if multiple chains are present in the CSV,
otherwise a single plot.

Usage:
    python3 evaluation/person_a/plots/plot_fig8_dedup_comparison.py \\
        <results_chain_dedup.csv> <output_dir>
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import apply_style, save_figure, PALETTE  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("output_dir")
    ap.add_argument("--chain", default=None,
                     help="plot only this chain_type (default: first chain found, "
                          "or use plot_fig8_all_chains for a multi-panel version)")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv_path)))
    chain = args.chain or rows[0]["chain_type"]
    rows = [r for r in rows if r["chain_type"] == chain]

    apply_style()
    fig, ax = plt.subplots(figsize=(3.4, 2.6))

    for version, color, label in [("old", PALETTE["old_code"], "Old code (permanent dedup)"),
                                    ("new", PALETTE["new_code"], "New code (episode-scoped dedup)")]:
        v_rows = sorted([r for r in rows if r["code_version"] == version],
                         key=lambda r: int(r["trial"]))
        if not v_rows:
            continue
        trials = [int(r["trial"]) for r in v_rows]
        cumulative = []
        running = 0
        for r in v_rows:
            running += int(r["fired"])
            cumulative.append(running)
        ax.plot(trials, cumulative, marker="o", markersize=3, color=color, label=label, linewidth=1.5)

    max_trial = max(int(r["trial"]) for r in rows)
    ax.plot([0, max_trial], [0, max_trial], linestyle=":", color="gray", linewidth=0.8,
             label="Ideal (1 per trial)")
    ax.set_xlabel("Trial number (each >120s apart)")
    ax.set_ylabel("Cumulative chain detections")
    ax.set_title(f"Effect of Episode-Scoped Dedup:\n{chain}", fontsize=8)
    ax.legend(fontsize=6)
    ax.set_xlim(0, max_trial + 0.5)
    ax.set_ylim(0, max_trial + 0.5)
    fig.tight_layout()
    pdf, png = save_figure(fig, args.output_dir, "fig8_dedup_comparison")
    print(f"Fig. 8 -> {pdf}")


if __name__ == "__main__":
    main()
