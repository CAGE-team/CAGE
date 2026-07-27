"""
Shared matplotlib style for every Person-A figure, so Fig. 1/3/4/5/8/10 look
like they belong to the same paper rather than five different defaults.

IEEE conventions applied: serif font (matches Times-based IEEE templates),
modest figure size sized for a single double-column figure slot (3.4in wide
is the standard IEEE single-column width; use FIGSIZE_WIDE for figures that
span both columns), colorblind-safe categorical palette (Okabe-Ito), and
saving both a .pdf (vector, for LaTeX \\includegraphics) and a .png (for
quick preview) for every figure.
"""
import os
import matplotlib

matplotlib.use("Agg")  # headless -- no display needed, this runs on a server/CLI
import matplotlib.pyplot as plt

FIGSIZE_SINGLE_COL = (3.4, 2.6)   # inches, IEEE single-column width
FIGSIZE_WIDE = (7.0, 3.2)         # inches, spans both columns

# Okabe-Ito palette: colorblind-safe, standard recommendation for scientific
# figures. Index 0 reserved for "fused"/"primary" series across figures so
# the same condition is always the same color everywhere in the paper.
PALETTE = {
    "fused": "#0072B2",        # blue
    "tetragon_only": "#E69F00", # orange
    "audit_only": "#009E73",    # green
    "old_code": "#D55E00",      # vermillion
    "new_code": "#0072B2",      # blue (matches "fused" -- both are "current/correct")
    "attack": "#D55E00",
    "benign": "#009E73",
    "neutral": "#56B4E9",
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def apply_style():
    plt.rcParams.update({
        "font.family": "serif",
        "font.size": 8,
        "axes.titlesize": 9,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "figure.dpi": 150,
        "savefig.dpi": 300,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "axes.grid": True,
        "grid.alpha": 0.25,
        "grid.linewidth": 0.5,
    })


def save_figure(fig, output_dir, basename):
    """Saves both <basename>.pdf (vector, for the paper) and <basename>.png
    (quick preview). Returns (pdf_path, png_path)."""
    os.makedirs(output_dir, exist_ok=True)
    pdf_path = os.path.join(output_dir, f"{basename}.pdf")
    png_path = os.path.join(output_dir, f"{basename}.png")
    fig.savefig(pdf_path, bbox_inches="tight")
    fig.savefig(png_path, bbox_inches="tight")
    return pdf_path, png_path
