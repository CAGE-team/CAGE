"""
Graph 2 — Attack vs Benign Alert Rate
Grouped bar chart: x = scenario, y = alert rate (0-100%), color = severity

Inputs:
  week4/results_personA_v2.csv  -> attack scenarios (presence of a row = fired)
  week4/results_benign.csv      -> benign scenarios (last column = fire count per trial)

Run this from ~/CAGE so the relative paths resolve correctly:
  python3 plot_graph2.py
"""
import csv
from collections import defaultdict
import matplotlib.pyplot as plt

ATTACK_CSV = "week4/results_personA_v2.csv"
BENIGN_CSV = "week4/results_benign.csv"
OUT_PNG = "week4/graph2_alert_rate.png"

# Severity used only for coloring the bars (attack techniques are the "real"
# detections; benign controls are grouped separately so FP-vs-TN is visually obvious)
SEVERITY = {
    "T1059_attack": "attack",
    "T1021_attack": "attack",
    "T1552_attack": "attack",
    "T1610_attack": "attack",
    "T1059_benign": "true_negative",
    "T1021_benign": "true_negative",
    "T1548_benign": "true_negative",
    "T1610_benign": "false_positive",
}

COLOR_MAP = {
    "attack": "#21918c",         # teal - matches viridis family from Graph 1
    "true_negative": "#440154",  # dark purple - correctly silent
    "false_positive": "#fde725", # yellow - warning / known limitation
}

# results_personA_v2.csv is populated by the interactive capture_latency.py
# tool, which only writes a row on a *successful* detection — a missed or
# timed-out trial is silently "not recorded" (see capture_latency.py). That
# means this file can only ever tell us how many trials succeeded, never
# how many were actually attempted. The methodology assumes exactly this
# many trials were run per technique; that can't be verified from the file
# alone, so any mismatch is surfaced loudly below instead of silently
# producing a wrong percentage.
EXPECTED_TRIALS_PER_TECHNIQUE = 10

def load_attack_rates(path):
    """Each row = one successfully detected trial. Alert rate = rows_seen /
    EXPECTED_TRIALS_PER_TECHNIQUE — see the constant's comment above for why
    that denominator can't be derived from the file itself."""
    counts = defaultdict(int)
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            counts[row["technique"]] += 1

    for tech, n in counts.items():
        if n > EXPECTED_TRIALS_PER_TECHNIQUE:
            raise ValueError(
                f"{path}: {n} successful rows recorded for {tech}, more than "
                f"the expected {EXPECTED_TRIALS_PER_TECHNIQUE} trials — data "
                f"looks corrupted or mixed from multiple runs."
            )
        if n < EXPECTED_TRIALS_PER_TECHNIQUE:
            print(f"WARNING: {tech} has only {n}/{EXPECTED_TRIALS_PER_TECHNIQUE} successful "
                  f"rows in {path}. This will be plotted as {n}/{EXPECTED_TRIALS_PER_TECHNIQUE} = "
                  f"{(n / EXPECTED_TRIALS_PER_TECHNIQUE) * 100:.0f}%, which assumes exactly "
                  f"{EXPECTED_TRIALS_PER_TECHNIQUE} trials were attempted for {tech} — "
                  f"capture_latency.py doesn't record timed-out trials, so that assumption "
                  f"can't be checked from the file alone. Confirm the actual trial count "
                  f"before trusting this number.")

    return {tech: (n / EXPECTED_TRIALS_PER_TECHNIQUE) * 100 for tech, n in counts.items()}

def load_benign_rates(path):
    """Each row = one trial with a 0/1 fire count in the last column."""
    fired = defaultdict(int)
    total = defaultdict(int)
    with open(path) as f:
        reader = csv.reader(f)
        for row in reader:
            # scenario_name, benign, technique, trial, fire_count
            technique = row[2]
            fire_count = int(row[4])
            total[technique] += 1
            if fire_count > 0:
                fired[technique] += 1
    return {tech: (fired[tech] / total[tech]) * 100 for tech in total}

attack_rates = load_attack_rates(ATTACK_CSV)
benign_rates = load_benign_rates(BENIGN_CSV)

# Order: attacks first (grouped), then benign controls (grouped) — makes the
# "detects real attacks, ignores benign activity" story read left-to-right
labels = []
values = []
colors = []

for tech in ["T1059", "T1021", "T1552", "T1610"]:
    labels.append(f"{tech}\n(attack)")
    values.append(attack_rates.get(tech, 0))
    colors.append(COLOR_MAP[SEVERITY[f"{tech}_attack"]])

for tech in ["T1059", "T1021", "T1548", "T1610"]:
    labels.append(f"{tech}\n(benign)")
    values.append(benign_rates.get(tech, 0))
    key = f"{tech}_benign"
    colors.append(COLOR_MAP[SEVERITY[key]])

fig, ax = plt.subplots(figsize=(10, 6))
bars = ax.bar(labels, values, color=colors, edgecolor="black", linewidth=0.6)

for bar, val in zip(bars, values):
    ax.text(bar.get_x() + bar.get_width() / 2, val + 2, f"{val:.0f}%",
            ha="center", va="bottom", fontsize=10, fontweight="bold")

ax.set_ylabel("Alert Rate (%)", fontsize=12)
ax.set_title("Attack Detection Rate vs. Benign False-Positive Rate", fontsize=14, fontweight="bold")
ax.set_ylim(0, 112)
ax.axvline(x=3.5, color="gray", linestyle="--", linewidth=1, alpha=0.6)
ax.text(1.5, 106, "Attack scenarios (want: high)", ha="center", fontsize=10, style="italic")
ax.text(5.5, 106, "Benign controls (want: low)", ha="center", fontsize=10, style="italic")

# Legend placed below the plot entirely so it never collides with bar labels,
# the divider annotations, or the title — no matter how the bars are ordered.
legend_elements = [
    plt.Rectangle((0, 0), 1, 1, facecolor=COLOR_MAP["attack"], edgecolor="black", label="Attack (true positive)"),
    plt.Rectangle((0, 0), 1, 1, facecolor=COLOR_MAP["true_negative"], edgecolor="black", label="Benign, correctly silent (true negative)"),
    plt.Rectangle((0, 0), 1, 1, facecolor=COLOR_MAP["false_positive"], edgecolor="black", label="Benign, incorrectly fired (false positive, documented)"),
]
ax.legend(handles=legend_elements, loc="upper center", bbox_to_anchor=(0.5, -0.12),
          ncol=1, fontsize=9, frameon=True)

plt.tight_layout()
plt.savefig(OUT_PNG, dpi=150, bbox_inches="tight")
print(f"Saved: {OUT_PNG}")

# Print the numbers too, for pasting straight into the paper
print("\n--- Alert rates ---")
for label, val in zip(labels, values):
    print(f"{label.replace(chr(10), ' '):25s} {val:.0f}%")
