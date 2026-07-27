#!/usr/bin/env python3
"""
Generates Tables 1, 2, 3, and 7 (Person A's tables) in both Markdown
(quick review) and LaTeX booktabs format (paste directly into the paper),
from the CSVs produced by the scripts in evaluation/person_a/scripts/.

Table 6 (related-work comparison) is not generated here -- it's a
literature table with no CSV backing it; see
evaluation/person_a/tables/table6_related_work_template.md instead.

Usage:
    python3 evaluation/person_a/tables/make_tables.py \\
        --detection-summary <results_detection_accuracy_summary.csv> \\
        --ablation <results_ablation_full.csv> \\
        --dedup <results_chain_dedup.csv> \\
        --param-sensitivity <results_parameter_sensitivity.csv> \\
        --output-dir <dir>

Any input can be omitted (that table is skipped) -- useful for generating
tables incrementally as each experiment's data becomes available.
"""
import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib.stats import wilson_ci  # noqa: E402


def _write(output_dir, basename, md_lines, latex_lines):
    os.makedirs(output_dir, exist_ok=True)
    md_path = os.path.join(output_dir, f"{basename}.md")
    tex_path = os.path.join(output_dir, f"{basename}.tex")
    with open(md_path, "w") as f:
        f.write("\n".join(md_lines) + "\n")
    with open(tex_path, "w") as f:
        f.write("\n".join(latex_lines) + "\n")
    return md_path, tex_path


def table1_detection_accuracy(csv_path, output_dir):
    rows = list(csv.DictReader(open(csv_path)))

    md = ["| Technique | TP | FP | FN | Precision | Recall (95% CI) | F1 | Source |",
          "|---|---|---|---|---|---|---|---|"]
    tex = [
        "\\begin{table}[t]",
        "\\centering",
        "\\caption{Per-technique detection accuracy (fused mode).}",
        "\\label{tab:detection-accuracy}",
        "\\begin{tabular}{lrrrrlll}",
        "\\toprule",
        "Technique & TP & FP & FN & Precision & Recall (95\\% CI) & F1 & Source \\\\",
        "\\midrule",
    ]
    for r in rows:
        tp, fn = int(r["tp"]), int(r["fn"])
        _, lo, hi = wilson_ci(tp, tp + fn) if (tp + fn) > 0 else (0, 0, 0)
        recall_str = f"{float(r['recall'])*100:.1f}\\% [{lo*100:.1f},{hi*100:.1f}]"
        recall_str_md = f"{float(r['recall'])*100:.1f}% [{lo*100:.1f}, {hi*100:.1f}]"
        star = "" if r["has_benign_control"].lower() == "true" else "*"
        md.append(f"| {r['technique']}{star} | {r['tp']} | {r['fp']} | {r['fn']} | "
                   f"{float(r['precision'])*100:.1f}% | {recall_str_md} | "
                   f"{float(r['f1'])*100:.1f}% | {r['source']} |")
        tex.append(f"{r['technique']}{star} & {r['tp']} & {r['fp']} & {r['fn']} & "
                    f"{float(r['precision'])*100:.1f}\\% & {recall_str} & "
                    f"{float(r['f1'])*100:.1f}\\% & {r['source']} \\\\")
    md.append("\n\\* no benign control constructed -- precision not meaningful (see "
               "run_detection_accuracy.py docstring)")
    tex += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return _write(output_dir, "table1_detection_accuracy", md, tex)


def table2_ablation_matrix(csv_path, output_dir):
    rows = list(csv.DictReader(open(csv_path)))
    counts = defaultdict(lambda: defaultdict(lambda: [0, 0]))
    for r in rows:
        counts[r["technique"]][r["condition"]][1] += 1
        if r["fired"] in ("1", "True", "true"):
            counts[r["technique"]][r["condition"]][0] += 1

    conditions = ["tetragon_only", "audit_only", "fused"]
    cond_labels = {"tetragon_only": "Tetragon only", "audit_only": "Audit log only", "fused": "Fused"}

    md = ["| Technique | " + " | ".join(cond_labels[c] for c in conditions) + " |",
          "|---|" + "---|" * len(conditions)]
    tex = ["\\begin{table}[t]", "\\centering",
           "\\caption{Ablation study: detection rate by telemetry configuration.}",
           "\\label{tab:ablation}",
           "\\begin{tabular}{l" + "r" * len(conditions) + "}", "\\toprule",
           "Technique & " + " & ".join(cond_labels[c] for c in conditions) + " \\\\", "\\midrule"]

    for tech in sorted(counts.keys()):
        row_md, row_tex = [tech], [tech]
        for c in conditions:
            fired, total = counts[tech][c]
            pct = f"{fired}/{total} ({fired/total*100:.0f}%)" if total else "N/A"
            row_md.append(pct)
            row_tex.append(pct.replace("%", "\\%"))
        md.append("| " + " | ".join(row_md) + " |")
        tex.append(" & ".join(row_tex) + " \\\\")
    tex += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return _write(output_dir, "table2_ablation_matrix", md, tex)


def table3_chain_dedup(csv_path, output_dir):
    rows = list(csv.DictReader(open(csv_path)))
    counts = defaultdict(lambda: defaultdict(int))
    totals = defaultdict(lambda: defaultdict(int))
    for r in rows:
        totals[r["chain_type"]][r["code_version"]] += 1
        if r["fired"] in ("1", "True", "true"):
            counts[r["chain_type"]][r["code_version"]] += 1

    md = ["| Chain | Old code (fired/N) | New code (fired/N) |", "|---|---|---|"]
    tex = ["\\begin{table}[t]", "\\centering",
           "\\caption{Chain correlation and episode-scoped deduplication results.}",
           "\\label{tab:chain-dedup}",
           "\\begin{tabular}{lll}", "\\toprule",
           "Chain & Old code (fired/N) & New code (fired/N) \\\\", "\\midrule"]
    for chain in sorted(totals.keys()):
        old = f"{counts[chain].get('old',0)}/{totals[chain].get('old',0)}" if totals[chain].get('old') else "not run"
        new = f"{counts[chain].get('new',0)}/{totals[chain].get('new',0)}" if totals[chain].get('new') else "not run"
        md.append(f"| {chain} | {old} | {new} |")
        tex.append(f"{chain} & {old} & {new} \\\\")
    tex += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return _write(output_dir, "table3_chain_dedup", md, tex)


def table7_parameter_sensitivity(csv_path, output_dir):
    rows = list(csv.DictReader(open(csv_path)))

    md = ["**Sweep results:**", "", "| Threshold | Fired/N |", "|---|---|"]
    tex = ["\\begin{table}[t]", "\\centering",
           "\\caption{Parameter sensitivity and evasion boundary results.}",
           "\\label{tab:param-sensitivity}",
           "\\begin{tabular}{ll}", "\\toprule", "Condition & Fired/N \\\\", "\\midrule"]

    sweep = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["mode"] == "sweep":
            sweep[r["independent_var"]][1] += 1
            if r["fired"] in ("1", "True", "true"):
                sweep[r["independent_var"]][0] += 1
    for thr in sorted(sweep.keys(), key=lambda x: int(x)):
        fired, total = sweep[thr]
        md.append(f"| {thr} | {fired}/{total} |")
        tex.append(f"Threshold={thr} & {fired}/{total} \\\\")

    md += ["", "**Evasion boundary results:**", "", "| Technique | Boundary | Fired/N |", "|---|---|---|"]
    evasion = defaultdict(lambda: [0, 0])
    for r in rows:
        if r["mode"] == "evasion":
            key = (r["technique"], r["independent_var"])
            evasion[key][1] += 1
            if r["fired"] in ("1", "True", "true"):
                evasion[key][0] += 1
    for (tech, boundary), (fired, total) in sorted(evasion.items()):
        md.append(f"| {tech} | {boundary} | {fired}/{total} |")
        tex.append(f"{tech} ({boundary}) & {fired}/{total} \\\\")

    tex += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return _write(output_dir, "table7_parameter_sensitivity", md, tex)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--detection-summary")
    ap.add_argument("--ablation")
    ap.add_argument("--dedup")
    ap.add_argument("--param-sensitivity")
    ap.add_argument("--output-dir", required=True)
    args = ap.parse_args()

    if args.detection_summary:
        md, tex = table1_detection_accuracy(args.detection_summary, args.output_dir)
        print(f"Table 1 -> {md}, {tex}")
    if args.ablation:
        md, tex = table2_ablation_matrix(args.ablation, args.output_dir)
        print(f"Table 2 -> {md}, {tex}")
    if args.dedup:
        md, tex = table3_chain_dedup(args.dedup, args.output_dir)
        print(f"Table 3 -> {md}, {tex}")
    if args.param_sensitivity:
        md, tex = table7_parameter_sensitivity(args.param_sensitivity, args.output_dir)
        print(f"Table 7 -> {md}, {tex}")

    if not any([args.detection_summary, args.ablation, args.dedup, args.param_sensitivity]):
        print("No inputs given -- nothing to generate. See --help.")


if __name__ == "__main__":
    main()
