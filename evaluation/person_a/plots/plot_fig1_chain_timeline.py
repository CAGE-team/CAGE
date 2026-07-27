#!/usr/bin/env python3
"""
Fig. 1 -- "Anatomy of a Detected Attack Chain": annotated event timeline
for one real T1021->T1059->T1552 execution, showing raw telemetry from
each of the 3 sources arriving and converging into the chain alert.

Unlike the other figures, this one is NOT generated from a CSV of many
trials -- it's a single, hand-picked representative run. Input format is a
tiny, manually-curated CSV of (t_offset_sec, source, label) triples, taken
directly from a real server log line-by-line (see
evaluation/person_a/README.md for how to extract one). A template with
placeholder timing is provided at
evaluation/person_a/csv_templates/fig1_timeline_example.csv -- replace with
real timestamps from an actual run before using in the paper.

Usage:
    python3 evaluation/person_a/plots/plot_fig1_chain_timeline.py \\
        <timeline.csv> <output_dir>
"""
import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from style import apply_style, save_figure  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402

SOURCE_COLORS = {
    "tetragon": "#E69F00",
    "audit": "#009E73",
    "correlator": "#0072B2",
}
SOURCE_Y = {"tetragon": 3, "audit": 1.3, "correlator": 0}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("csv_path")
    ap.add_argument("output_dir")
    args = ap.parse_args()

    rows = list(csv.DictReader(open(args.csv_path)))

    apply_style()
    fig, ax = plt.subplots(figsize=(7.0, 3.2))

    # Stagger label vertical offset when points on the same row land close
    # together in time (e.g. several process_exec events a few hundred ms
    # apart) -- otherwise their text labels overlap illegibly. Track the
    # last labeled x-position per row and increase the stack level whenever
    # the new point is within CLUSTER_GAP of it.
    CLUSTER_GAP = max(1.0, (max(float(r["t_offset_sec"]) for r in rows) -
                            min(float(r["t_offset_sec"]) for r in rows)) * 0.03)
    last_t_per_row = {}
    stack_per_row = {}

    for r in rows:
        t = float(r["t_offset_sec"])
        source = r["source"]
        y = SOURCE_Y.get(source, 1.5)
        color = SOURCE_COLORS.get(source, "gray")
        marker = "*" if source == "correlator" else "o"
        size = 120 if source == "correlator" else 50
        ax.scatter([t], [y], color=color, marker=marker, s=size, zorder=3,
                    edgecolors="black", linewidths=0.5)

        if source in last_t_per_row and (t - last_t_per_row[source]) < CLUSTER_GAP:
            stack_per_row[source] = stack_per_row.get(source, 0) + 1
        else:
            stack_per_row[source] = 0
        last_t_per_row[source] = t

        # Labels point AWAY from the middle row (audit), not toward it --
        # pointing every row's labels into the same central gap is what
        # caused tetragon/audit labels to collide in the first version of
        # this figure. Top row (tetragon) goes up, bottom row (correlator)
        # goes down, middle row (audit) goes up into the now-larger gap.
        if source == "correlator":
            base_dy, step = -14, -11
        else:
            base_dy, step = 10, 11
        dy = base_dy + stack_per_row[source] * step
        ax.annotate(r["label"], (t, y), textcoords="offset points",
                     xytext=(0, dy), ha="center", fontsize=6,
                     arrowprops=dict(arrowstyle="-", color="gray", linewidth=0.4,
                                      shrinkA=0, shrinkB=4) if stack_per_row[source] > 0 else None)

    ax.set_yticks([0, 1.3, 3])
    ax.set_yticklabels(["CausalGraph\n(chain alert)", "K8s Audit Log", "Tetragon eBPF"])
    ax.set_xlabel("Time since first event (seconds)")
    ax.set_title("Anatomy of a Detected Attack Chain: T1021→T1059→T1552", fontsize=9, pad=28)
    ax.set_ylim(-0.9, 4.0)
    ax.grid(axis="x", alpha=0.25)
    ax.grid(axis="y", visible=False)
    fig.tight_layout()
    pdf, png = save_figure(fig, args.output_dir, "fig1_chain_timeline")
    print(f"Fig. 1 -> {pdf}")


if __name__ == "__main__":
    main()
