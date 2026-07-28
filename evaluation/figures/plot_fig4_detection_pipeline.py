#!/usr/bin/env python3
"""
Fig. 4 -- conceptual (not data-driven) diagram for System Design SIV-F,
illustrating the detection pipeline every normalized event passes
through: a fan-out of independent per-technique checks, and, in
parallel, the shared per-pod-UID temporal window that feeds the five
documented chain checks. Matches the content spec already agreed for
this figure: one normalized event entering independent technique
checks, the shared window feeding the chain checks, alerts and graph
updates as the two outputs.

Lives outside person_a/ and person_b/ for the same reason Fig. 1 does:
it is a fixed architectural illustration, not derived from trial data.

Usage:
    python3 evaluation/figures/plot_fig4_detection_pipeline.py <output_dir>
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "person_a", "plots"))
from style import apply_style, save_figure, PALETTE  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402
from matplotlib.patches import FancyArrowPatch  # noqa: E402


def box(ax, xy, w, h, text, facecolor, edgecolor="black", fontsize=7.2,
        fontweight="normal", zorder=2, textcolor="black"):
    x, y = xy
    p = FancyBboxPatch((x, y), w, h,
                        boxstyle="round,pad=0.02,rounding_size=0.04",
                        linewidth=0.9, edgecolor=edgecolor,
                        facecolor=facecolor, zorder=zorder)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
             fontsize=fontsize, fontweight=fontweight, zorder=zorder + 1,
             color=textcolor, wrap=True)
    return p


def arrow(ax, start, end, color="black", style="-|>", lw=1.1,
          connectionstyle="arc3,rad=0.0"):
    a = FancyArrowPatch(start, end, arrowstyle=style, mutation_scale=10,
                         linewidth=lw, color=color,
                         connectionstyle=connectionstyle, zorder=3)
    ax.add_patch(a)


def main():
    ap_out = sys.argv[1] if len(sys.argv) > 1 else "."
    apply_style()

    fig, ax = plt.subplots(figsize=(7.0, 4.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7.2)
    ax.axis("off")

    # Entry point
    box(ax, (2.9, 6.2), 4.2, 0.7,
        "Normalized event\n(from Tetragon or audit-log consumer)",
        facecolor=PALETTE["neutral"], fontweight="bold")

    # Fan out into two parallel paths
    arrow(ax, (4.3, 6.2), (2.3, 5.3), color="black",
          connectionstyle="arc3,rad=-0.1")
    arrow(ax, (5.7, 6.2), (7.7, 5.3), color="black",
          connectionstyle="arc3,rad=0.1")

    # Left path: per-technique checks
    box(ax, (0.3, 4.55), 4.0, 0.75,
        "11 independent technique checks\n(Table I), each tested against\n"
        "this event or its pod's window",
        facecolor="#f2f2f2", fontsize=6.8)
    arrow(ax, (2.3, 4.55), (2.3, 3.7), color="black")
    box(ax, (0.7, 3.0), 3.2, 0.6, "Per-technique alert",
        facecolor=PALETTE["attack"], fontweight="bold", textcolor="white")

    # Right path: shared window feeding chain checks
    box(ax, (5.7, 4.55), 4.0, 0.75,
        "Shared per-pod-UID window\n(120s, holds recent normalized\n"
        "events for that workload)",
        facecolor="#f2f2f2", fontsize=6.8)
    arrow(ax, (7.7, 4.55), (7.7, 3.7), color="black")
    box(ax, (5.9, 3.0), 3.6, 0.6,
        "5 documented chain checks\n(co-occurrence within the window)",
        facecolor="#f2f2f2", fontsize=6.5)
    arrow(ax, (7.7, 3.0), (7.7, 2.15), color="black")
    box(ax, (6.1, 1.55), 3.2, 0.6, "Chain alert (CRITICAL)",
        facecolor=PALETTE["fused"], fontweight="bold", textcolor="white")

    # Both outputs converge
    arrow(ax, (2.3, 3.0), (4.6, 1.05), color=PALETTE["attack"],
          connectionstyle="arc3,rad=0.15")
    arrow(ax, (7.7, 1.55), (5.4, 1.05), color=PALETTE["fused"],
          connectionstyle="arc3,rad=-0.15")

    box(ax, (2.9, 0.3), 4.2, 0.7,
        "Causal graph node update\n+ live dashboard (SSE)",
        facecolor=PALETTE["neutral"], fontweight="bold")

    fig.tight_layout()
    pdf, png = save_figure(fig, ap_out, "fig4_detection_pipeline")
    print(f"Fig. 4 -> {pdf}")


if __name__ == "__main__":
    main()
