# Person A's Evaluation Kit

Scripts, plotting/table templates, and documentation for Person A's share of
the CAGE evaluation (E1, E2, E3, E7, E9, plus E10 once its prerequisite is
approved — see `../../EVALUATION_REVIEW.md`). Nothing in `src/`, `week4/`,
or any other existing project file was modified to build this — everything
here is new.

## Folder structure

```
evaluation/person_a/
├── README.md                        (this file)
├── THREAT_MODEL_DRAFT.md            (Gap 5 -- paper text, not a script)
├── REPRODUCIBILITY_CHECKLIST.md     (Gap 6 -- fill in from your machine)
├── lib/                             (shared helpers, all unit-tested -- see below)
│   ├── stats.py                     (Wilson CI, precision/recall/F1)
│   ├── param_patch.py               (runtime threshold overrides, no source edits)
│   └── wait_for_alert.py            (shared log-tailing detection-wait logic)
├── scripts/                         (the 5 experiment runners)
│   ├── launch_server_with_params.py (drop-in `python3 src/server.py` replacement,
│   │                                 applies threshold overrides first)
│   ├── run_ablation_full.py         (E2 -- all 11 techniques, fixes the broken
│   │                                 T1610 entry in the original run_ablation.py)
│   ├── run_detection_accuracy.py    (E1 -- wires week4/metrics.py + CIs)
│   ├── run_chain_dedup_comparison.py (E3)
│   ├── run_parameter_sensitivity.py (E7 sweep + E9 evasion, merged)
│   └── run_window_sensitivity.py    (E10 -- BLOCKED, see Gap 3 below)
├── csv_templates/                   (header-only reference files, exact
│                                     schema each script actually writes)
├── plots/                           (one script per figure + shared style.py)
└── tables/                          (make_tables.py generates Tables 1/2/3/7
                                      in both Markdown and LaTeX)
```

## What's been verified, and what still needs a live cluster

Built while the cluster/Docker was unreachable from this environment (a
host-level Docker Desktop issue, outside anything fixable from here). This
was NOT skipped silently -- everything that could be tested without a
cluster was tested for real:

- **`lib/stats.py`**: full self-test, run directly (`python3 lib/stats.py`)
  -- verified against known Wilson interval behavior (no false zero-width
  CIs at 0%/100%).
- **`lib/param_patch.py`**: verified two ways -- a mechanism self-test
  (`python3 lib/param_patch.py`), AND a direct test against the REAL
  `src.causal_graph.CausalGraph` class proving a patched
  `CONNECTION_BURST_THRESHOLD` actually changes live detection behavior
  (fires T1610 at 3 connections instead of 5). This is the piece the whole
  parameter-sensitivity experiment depends on, and it's the most rigorously
  checked thing in this folder.
- **`lib/wait_for_alert.py`**: synthetic test proving it correctly ignores
  pre-existing log lines and only matches new ones written during the poll
  window.
- **`scripts/launch_server_with_params.py`**: run for real against the
  actual (currently unreachable) cluster -- confirmed it applies the patch
  and then hits the exact same `FATAL: cannot reach Kubernetes API server`
  failure `python3 src/server.py` itself would, proving correct handoff.
- **All 5 experiment scripts**: syntax-checked, `--help` verified, argument
  validation paths tested (e.g. `run_chain_dedup_comparison.py` correctly
  rejects a `--gap` under 120s; `run_parameter_sensitivity.py` correctly
  rejects `--mode sweep` without `--threshold`).
- **All plotting scripts**: run against hand-built synthetic CSVs matching
  the real schemas, output PNGs visually inspected. Two real bugs were
  found and fixed this way: Fig. 5's footnote marker overlapped the
  colorbar, and Fig. 1's clustered event labels overlapped each other and
  then the title/axis after the first fix -- both corrected, both re-
  verified visually.
- **`tables/make_tables.py`**: run against the same synthetic CSVs, output
  checked in both Markdown and LaTeX.

**What genuinely cannot be verified without the cluster, and must happen
before trusting real results:** whether firing an actual attack against a
running server produces the exact log line format `wait_for_alert.py`
expects, and the actual magnitude/shape of real data (the synthetic data
above was hand-built to be *plausible*, not measured). Do a small (N=2-3)
live run of each script the moment the cluster is back, exactly the way
`run_benign_controls.py` was smoke-tested earlier in this project's
history, before committing to a full N=15-20 run.

## Prerequisite before running E9's T1610/T1499/T1613 checks or any E7 sweep

None -- `run_parameter_sensitivity.py --mode evasion` and
`run_ablation_full.py`/`run_detection_accuracy.py` work against an
unmodified checkout. Only `--mode sweep` needs the server started via
`launch_server_with_params.py` with an env var override (no source change
needed, since the three swept constants are already plain module
attributes).

## Prerequisite before running E10 (window sensitivity)

**Blocked** until the one-line source change in `EVALUATION_REVIEW.md`
Gap 3 is applied and approved (extracting the hardcoded `timedelta(seconds=120)`
literal into a named, env-overridable `CORRELATION_WINDOW_SECONDS` constant).
`run_window_sensitivity.py` will fail immediately with a clear message if
run before that -- this is intentional, not a bug to work around.

## Recommended run order and rough wall-clock budget

1. **Sanity pass (do this first, always):** start a `fused`-mode server,
   run each script with a tiny `--trials 2` to confirm the log-matching
   actually works against real output before committing to a long run.
   ~15 min.
2. **E2 (ablation, `run_ablation_full.py`)** -- 11 techniques x 10 trials x
   3 conditions = 330 trials, up to 60s wait each in the worst case.
   Budget a full unattended session (several hours) per condition; restart
   the server between conditions per the script's confirmation prompt.
3. **E1 (detection accuracy, `run_detection_accuracy.py`)** -- 11
   techniques x up to 2x15 trials (attack + benign where applicable).
   Run against `fused` mode. Budget 1-2 hours.
4. **E3 (chain dedup, `run_chain_dedup_comparison.py`)** -- 5 chains x 10
   trials x 130s gap = ~108 minutes of gaps alone, plus attack execution
   time. This is the highest-value, lowest-additional-effort item once
   you're already set up, so don't skip it. For the before/after
   comparison against the OLD (permanently-deduped) code:
   ```
   git log --oneline | grep -i "chain expiration"   # find the pre-fix commit
   git worktree add /tmp/cage-old-dedup <commit-before-the-fix>
   cd /tmp/cage-old-dedup
   ABLATION_MODE=fused python3 src/server.py &
   python3 <path-to-this-repo>/evaluation/person_a/scripts/run_chain_dedup_comparison.py \
       <old-server-logfile> <same-outfile-as-the-new-run> --code-version old
   cd -
   git worktree remove /tmp/cage-old-dedup
   ```
   Using `git worktree` rather than checking out a branch in-place means
   your main working directory (and this evaluation folder) are never
   touched by the comparison run.
5. **E9 (evasion, `run_parameter_sensitivity.py --mode evasion`)** -- 3
   techniques x 2 boundaries x 10 trials, default thresholds, no server
   restart needed. ~30-45 min.
6. **E7 (sweep, `run_parameter_sensitivity.py --mode sweep`)** -- optional,
   cut first if short on time. 8 threshold values x 10 trials each,
   restarting the server via `launch_server_with_params.py` between values.
   Budget 2+ hours.
7. **Generate figures and tables** once the CSVs above exist:
   ```
   python3 plots/plot_fig1_chain_timeline.py <hand-curated-timeline.csv> output/
   python3 plots/plot_fig3_4_ablation.py output/results_ablation_full.csv output/
   python3 plots/plot_fig5_technique_prf.py output/results_detection_accuracy_summary.csv output/
   python3 plots/plot_fig8_dedup_comparison.py output/results_chain_dedup.csv output/
   python3 plots/plot_fig10_parameter_sensitivity.py output/results_parameter_sensitivity.csv output/
   python3 tables/make_tables.py --detection-summary output/results_detection_accuracy_summary.csv \
       --ablation output/results_ablation_full.csv --dedup output/results_chain_dedup.csv \
       --param-sensitivity output/results_parameter_sensitivity.csv --output-dir output/
   ```

Total, if running everything including the bonus E7/E10: budget roughly
2-3 full days of mostly-unattended wall-clock time (most of it is waiting
out `sleep`/detection-wait windows, not active work) -- plan accordingly
against your submission deadline, and cut E7/E10 first if squeezed.

## Fig. 1's input needs manual curation

Every other figure is generated straight from a CSV of many trials. Fig. 1
(the attack-chain timeline) is deliberately a single, hand-picked
representative example -- pull the real timestamps from one clean
`run_detection_accuracy.py` or `run_ablation_full.py` server log (grep for
the relevant `[QUEUED]`/`[AUDIT]`/chain-alert lines, compute offsets from
the first event), fill them into a CSV matching
`csv_templates/fig1_timeline_example.csv`'s format, and regenerate. Do a
visual check after -- the label-stacking logic handles closely-spaced
events reasonably well but this is an illustrative figure, not a fully
automated one, and is worth a five-minute look before it goes in the paper.
