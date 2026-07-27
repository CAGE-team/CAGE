#!/usr/bin/env python3
"""
Fig. 1 -- conceptual (not data-driven) diagram for the Introduction,
illustrating the cross-layer visibility gap that motivates CAGE: what
eBPF (Tetragon) sees/misses, what the Kubernetes audit log sees/misses,
and how CAGE bridges the two via the pod UID into one causal graph.

This is the paper's first figure by reading order, so it is numbered
Fig. 1. It lives outside person_a/ and person_b/ since it is not derived
from either evaluator's trial data -- it is a fixed architectural/
motivational illustration, built once and not regenerated from a CSV.

Usage:
    python3 evaluation/figures/plot_fig1_visibility_gap.py <output_dir>
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "..", "person_a", "plots"))
from style import apply_style, save_figure, PALETTE  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.patches import FancyBboxPatch  # noqa: E402
from matplotlib.patches import FancyArrowPatch  # noqa: E402


def box(ax, xy, w, h, text, facecolor, edgecolor="black", fontsize=7.5,
        fontweight="normal", zorder=2):
    x, y = xy
    p = FancyBboxPatch((x, y), w, h,
                        boxstyle="round,pad=0.02,rounding_size=0.04",
                        linewidth=0.9, edgecolor=edgecolor,
                        facecolor=facecolor, zorder=zorder)
    ax.add_patch(p)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
             fontsize=fontsize, fontweight=fontweight, zorder=zorder + 1,
             wrap=True)
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

    fig, ax = plt.subplots(figsize=(7.0, 3.6))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 6.2)
    ax.axis("off")

    # Source column headers
    box(ax, (0.3, 4.9), 4.1, 0.7, "eBPF (Tetragon)\nkernel-level telemetry",
        facecolor=PALETTE["tetragon_only"], fontweight="bold")
    box(ax, (5.6, 4.9), 4.1, 0.7,
        "Kubernetes Audit Log\ncontrol-plane telemetry",
        facecolor=PALETTE["audit_only"], fontweight="bold")

    # "Sees" / "Misses" panels under each source
    box(ax, (0.3, 3.35), 4.1, 1.35,
        "Sees: shell exec, TCP connections,\ndangerous syscalls, capabilities\n\n"
        "Misses: kubectl exec sessions,\nRBAC changes, secret reads via API",
        facecolor="#f2f2f2", fontsize=6.8)
    box(ax, (5.6, 3.35), 4.1, 1.35,
        "Sees: API calls, RBAC and identity\ncontext, secret reads via API\n\n"
        "Misses: shells spawned inside a pod,\nlateral connections between pods",
        facecolor="#f2f2f2", fontsize=6.8)

    # Convergence arrows into the pod-UID join
    arrow(ax, (2.35, 3.35), (4.55, 2.15), color=PALETTE["tetragon_only"],
          connectionstyle="arc3,rad=-0.15")
    arrow(ax, (7.65, 3.35), (5.45, 2.15), color=PALETTE["audit_only"],
          connectionstyle="arc3,rad=0.15")

    # Pod UID join box
    box(ax, (3.55, 1.55), 2.9, 0.65,
        "Same workload, joined on pod UID\n(fixed for the pod's lifetime)",
        facecolor="white", edgecolor=PALETTE["fused"], fontsize=6.8,
        fontweight="bold")

    arrow(ax, (5.0, 1.55), (5.0, 0.95), color=PALETTE["fused"], lw=1.4)

    # CAGE causal graph box
    box(ax, (2.9, 0.25), 4.2, 0.7,
        "CAGE causal graph\ntechnique + chain correlation",
        facecolor=PALETTE["fused"], edgecolor=PALETTE["fused"],
        fontsize=8, fontweight="bold")
    # white text on the blue CAGE box
    ax.texts[-1].set_color("white")

    fig.tight_layout()
    pdf, png = save_figure(fig, ap_out, "fig1_visibility_gap")
    print(f"Fig. 1 -> {pdf}")


if __name__ == "__main__":
    main()
