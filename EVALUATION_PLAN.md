# CAGE — IEEE Paper Evaluation Plan

Final pre-submission evaluation roadmap. Optimized for reviewer confidence: every
experiment either (a) proves a specific claim CAGE's design depends on, or (b)
honestly characterizes a real limitation instead of hiding it. Nothing here is
generic — every procedure references CAGE's actual constants, scripts, and code
paths as they exist in this repo today.

**Team split:** Person A owns *correctness* (does it detect the right things,
and does the cross-layer design actually matter). Person B owns *systems
behavior* (does it perform well, cost little, and survive failure). This split
lets both of you work in parallel with almost no cross-dependency — Person B
only needs a running `fused`-mode server, same as Person A.

---

## 0. Prerequisite: one small code change before Person A's E7

`CONNECTION_BURST_THRESHOLD` (`src/causal_graph.py:42`, currently `5`) is a
hardcoded module constant. E7 (threshold sensitivity) needs to sweep it without
editing source between runs. Add before starting evaluation:

```python
# src/causal_graph.py, near the other T1610 constants
import os
CONNECTION_BURST_THRESHOLD = int(os.environ.get("T1610_BURST_THRESHOLD", "5"))
```

This is a one-line, behavior-preserving change (default unchanged at 5) —
verify with `python3 -m py_compile src/causal_graph.py` and one live T1610 fire
before either of you starts collecting data on it.

---

## 1. Master experiment index

| # | Experiment | Owner | Figure(s) | Table | Section |
|---|---|---|---|---|---|
| E1 | Per-technique detection accuracy | A | Fig 5 | Table 1 | Detection Accuracy |
| E2 | Cross-layer ablation (all 11 techniques) | A | Fig 3, Fig 4 | Table 2 | Ablation Study |
| E3 | Chain correlation + dedup correctness | A | Fig 1, Fig 8 | Table 3 | Detection Accuracy |
| E4 | Detection latency distribution + connection-age effect | B | Fig 6, Fig 7 | Table 4 | Performance |
| E5 | Resource overhead | B | Fig 9 | Table 5 | Overhead |
| E6 | NetworkMonitor polling scalability | B | — (supplementary) | Table 5b | Overhead |
| E7 | T1610 threshold sensitivity (bonus) | A | Fig 10 | Table 7 | Ablation |
| E8 | Fault injection / recovery | B | Fig 2 | — | System Robustness |
| — | Related-work comparison (literature, no experiment) | joint | — | Table 6 | Related Work |

E1–E5, E8 are **core** — treat as non-negotiable for the submission. E6 is a
small supplementary table, cheap to collect. E7 is the one item to cut first
if you're short on time.

---

## 2. Full experiment specifications

### E1 — Per-technique detection accuracy

- **Objective / hypothesis:** CAGE detects each of its 11 MITRE techniques with
  high recall and near-zero false positives when run in `fused` mode. This is
  the paper's headline detection-accuracy claim.
- **Test procedure:** For each of the 11 techniques, run N=15 malicious trials
  (existing attack commands from `week4/simulate_full_suite.sh` /
  `run_ablation.py` / `run_t1548_trials.sh`, one per technique) and N=15 benign
  trials (extend `week4/run_benign_controls.py`'s category list from 4 to all
  11 — the pattern is already established, it's mechanical to extend). Feed
  every `(alert, timestamp)` and `(injected_attack, timestamp)` pair into
  `week4.metrics.MetricsCollector` (already fixed this session to correctly
  match by technique + time window instead of the old `"T105" in rule`
  substring bug) to compute TP/FP/FN per technique.
- **Inputs/workload:** `attacker` pod for malicious trials; `legitimate-app`
  and `benign-worker` for benign trials (per the namespace-only scope design —
  no pod is exempt, so any non-system pod is a valid benign-control target).
  ABLATION_MODE=fused.
- **Expected output:** Recall ≥ 90% for every technique (matching the ablation
  study's already-observed 9/10 for T1059 — Tetragon occasionally misses a
  trial, document why if it recurs), Precision at or near 100% for the 9
  techniques with real scope exclusion; **document, don't hide**, that T1021
  and T1610 have known non-zero FP characteristics (T1021 has no scope
  exclusion at all — any `kubectl exec` into any pod fires it; T1610's FP rate
  depends on the burst threshold, covered separately in E7).
- **CSV to collect:** `week4/results_detection_accuracy.csv` — columns:
  `technique, trial, ground_truth(attack|benign), fired(0|1), latency_sec,
  severity`.
- **Best visualization:** A **heatmap** of Precision/Recall/F1 (rows = 11
  techniques, columns = 3 metrics, cell color = value 0–1) rather than a bar
  chart — a bar chart with 11×3 bars is unreadable; a heatmap is scannable in
  one glance and standard in detection-system papers.
- **Figure title:** *"Fig. 5 — Per-Technique Precision, Recall, and F1-Score
  Across 11 MITRE ATT&CK Techniques (Fused Mode)."*
- **Table:** Table 1 — raw TP/FP/FN/N counts backing Fig. 5 (reviewers expect
  the raw counts alongside any derived-metric figure).
- **Section:** Detection Accuracy.

---

### E2 — Cross-layer ablation study (extended to all 11 techniques)

- **Objective / hypothesis:** No single telemetry source (Tetragon eBPF alone,
  or K8s audit log alone) covers all 11 techniques — the cross-layer fusion is
  architecturally necessary, not a convenience. This is CAGE's central design
  claim and the one most reviewers will scrutinize first.
- **Test procedure:** Extend `run_ablation.py`'s `TECHNIQUES` dict (currently
  T1059/T1021/T1552/T1610 only) to all 11. Run each technique × 10 trials ×
  3 conditions (`ABLATION_MODE=tetragon_only|audit_only|fused`), restarting the
  server between conditions per the script's existing confirmation prompt.
  330 trials total.
- **Inputs/workload:** Same attack commands as E1, run once per condition.
- **Expected output:** A clean split — Tetragon-sourced techniques
  (T1059, T1610, T1611, T1548, T1496, T1499) show 0/10 under `audit_only`;
  audit-sourced techniques (T1021, T1552, T1548-PRIV-POD, T1548.005, T1613)
  show 0/10 under `tetragon_only`; `fused` recovers full detection on both.
  This directly extends the existing 4-technique table already in README.
- **CSV to collect:** `week4/results_ablation_full.csv` — same schema as the
  existing `results_ablation.csv` (`condition, technique, trial, fired`), just
  covering all 11 techniques instead of 4.
- **Best visualization:** Two complementary figures, not one bar chart:
  1. A **heatmap** (11 techniques × 3 conditions, cell = detection rate %) —
     precise, compact, the primary evidence figure.
  2. A **radar chart** with one axis per MITRE tactic (Execution, Lateral
     Movement, Credential Access, Privilege Escalation, Discovery, Impact) and
     three overlaid traces (tetragon_only / audit_only / fused), each showing
     % of that tactic's techniques detected. This is a genuinely appropriate
     use of a radar chart — it's a multi-dimensional comparison across
     categorical axes with 3 overlaid conditions, exactly radar's strength —
     and tells a *shape* story (audit_only and tetragon_only cover
     complementary, non-overlapping wedges; fused covers the full silhouette)
     that the heatmap's precise numbers don't visually convey as immediately.
- **Figure titles:** *"Fig. 3 — Detection Rate by Telemetry Source and
  Technique (Ablation Heatmap)."* / *"Fig. 4 — MITRE ATT&CK Tactic Coverage by
  Telemetry Configuration."*
- **Table:** Table 2 — full ablation matrix (11 × 3, detection rate + raw
  fired/N).
- **Section:** Ablation Study.

---

### E3 — Chain correlation accuracy and episode-scoped deduplication

- **Objective / hypothesis:** (a) CAGE correctly correlates individual
  technique alerts into all 5 documented CRITICAL chains within the 120s
  window; (b) the episode-scoped chain deduplication (fires once per
  incident, re-arms once the condition clears) does not undercount repeated,
  independent trials against the same reused `attacker` pod — this is the
  exact scenario every other script in this repo actually runs.
- **Test procedure:** For each of the 5 chains, run 10 sequential trials
  against the same `attacker` pod, each trial separated by >120s (so each is
  a genuinely independent episode by the window's own definition). Record
  whether each trial re-fires the chain alert. **Bonus, high-value:** `git
  show <commit-before-this-session>:src/causal_graph.py` still has the old
  permanent-dedup version — run the identical 10-trial sequence against that
  version too (checkout to a scratch branch, don't touch main) for a genuine
  before/after comparison.
- **Inputs/workload:** `attacker` pod, `week4/simulate_full_suite.sh`'s
  individual chain-triggering command sequences, run in isolation per chain
  rather than the full combined suite.
- **Expected output:** New code: 10/10 fires per chain (episode-scoped dedup
  re-arms correctly). Old code (if you run the comparison): 1/10 — only the
  first trial fires, the remaining 9 are silently suppressed by the permanent
  latch.
- **CSV to collect:** `week4/results_chain_dedup.csv` — columns: `chain_type,
  trial, code_version(old|new), fired(0|1), timestamp`.
- **Best visualization:** A **line graph** of cumulative chain detections vs.
  trial number, two series (old vs. new code) — old flatlines at 1 after
  trial 1, new is a straight diagonal (1 per trial). This is one of the
  strongest figures available to you: it's data-backed proof of a specific,
  named engineering fix, which is rare and compelling in a systems paper.
  Complement with a **timeline** figure for a single successful chain
  (Fig. 1) showing raw events from all 3 sources arriving and converging into
  one alert — use this as the opening figure of the Detection Accuracy
  section, before any aggregate statistics, so the reader has a concrete
  mental model of what "a detection" actually looks like.
- **Figure titles:** *"Fig. 1 — Anatomy of a Detected Attack Chain: Raw
  Telemetry Timeline for T1021→T1059→T1552."* / *"Fig. 8 — Effect of
  Episode-Scoped Deduplication on Repeated-Trial Chain Detection Rate."*
- **Table:** Table 3 — per-chain trial results (5 chains × 10 trials,
  detected count, dedup behavior).
- **Section:** Detection Accuracy.

---

### E4 — Detection latency distribution and connection-age characterization

- **Objective / hypothesis:** (a) characterize true end-to-end detection
  latency as a *distribution*, not a single averaged number (the existing
  DEMO_GUIDE 5-trial table already shows real spread: 4.1s–11.0s); (b)
  formally characterize the connection-age-dependent Tetragon delivery lag
  already found and root-caused this session (fresh connection: sub-second;
  connection open ~30s+: ~30s lag) as a documented systems finding, not a bug
  to sweep under the rug.
- **Test procedure:** Using `week4/capture_latency.py` (wait window already
  widened to 60s this session), run N=20 trials each for a Tetragon-sourced
  technique (T1059) and an audit-sourced technique (T1552), recording actual
  wall-clock latency per trial. Separately, for the connection-age
  experiment: restart the server, fire T1059 trials at fixed elapsed times
  since consumer startup (5s, 15s, 30s, 60s, 120s), recording latency at each
  point.
- **Inputs/workload:** `attacker` pod, same commands as E1/E2.
- **Expected output:** Audit-sourced detections cluster tightly under 2s
  (confirmed this session: ~1s). Tetragon-sourced detections show a bimodal
  distribution — fast when connection is young, a long tail once the
  connection has been open a while. The connection-age sweep should show
  latency visibly increasing with elapsed connection time.
- **CSV to collect:** `week4/results_latency.csv` (from `capture_latency.py`,
  already has the right schema: `person,technique,trial,t0,t1,latency_sec`)
  plus `week4/results_latency_by_connage.csv` — columns: `connection_age_sec,
  trial, latency_sec, source(tetragon|audit)`.
- **Best visualization:**
  1. A **CDF plot** — X = latency (seconds), Y = fraction of trials detected
     within X — one line per source (Tetragon vs. audit). Far more
     informative than a bar-chart average: shows the audit line reaching
     Y=1.0 almost immediately, and the Tetragon line's long tail, in one
     figure.
  2. A **scatter plot with fitted trend line** — X = connection age at fire
     time, Y = observed latency — direct visual evidence for the root-cause
     finding.
- **Figure titles:** *"Fig. 6 — Cumulative Distribution of End-to-End
  Detection Latency by Telemetry Source."* / *"Fig. 7 — Detection Latency as
  a Function of Tetragon Stream Connection Age."*
- **Table:** Table 4 — latency statistics (min / median / mean / p95 / max)
  per technique and per source.
- **Section:** Performance. (Fig. 7 in particular is good material for a
  short "Systems Characterization" or "Lessons Learned" subsection — most
  papers don't report this kind of honest operational finding, and it reads
  as rigor, not weakness, if framed as "we measured and explain a real
  effect" rather than hidden.)

---

### E5 — Resource overhead

- **Objective / hypothesis:** CAGE's runtime cost (CPU, memory) is modest and
  bounded over time (validates the periodic stale-pod sweep fix in
  `causal_graph.py` — without it, tracked-pod state grows unboundedly).
- **Test procedure:** Sample CPU% and RSS (via `ps -o %cpu,rss -p <pid>` or
  `docker stats` for the Tetragon container) every 5s for the CAGE server
  process, across three phases: (1) 5 min idle, (2) 10 min running
  `simulate_full_suite.sh` repeatedly back-to-back, (3) 5 min idle again post
  load. Also measure a `CAGE OFF` baseline (Tetragon + cluster only) for
  comparison.
- **Inputs/workload:** New script `week4/measure_overhead.py` — a simple
  sampling loop around `ps`/`docker stats`, no new detection logic touched.
- **Expected output:** CPU/memory stay flat and bounded in phases 1 and 3
  (proving the sweep fix works over real wall-clock time, not just the
  synthetic 500-event-threshold unit test done this session), with a
  moderate, explainable bump during phase 2's active load.
- **CSV to collect:** `week4/results_overhead.csv` — columns: `timestamp,
  phase(idle_pre|active|idle_post|baseline), component(server|tetragon),
  cpu_pct, rss_mb`.
- **Best visualization:** A **stacked area chart** (or multi-line chart if
  overlap makes stacking unclear) of CPU%/memory over time, phase boundaries
  marked with vertical reference lines — shows the bounded, flat post-load
  behavior directly, which a single bar-chart average cannot.
- **Figure title:** *"Fig. 9 — CAGE Resource Utilization Over Time Across
  Idle, Active-Detection, and Post-Load Phases."*
- **Table:** Table 5 — overhead summary (mean/peak CPU%, mean/peak RSS, per
  phase and per component).
- **Section:** Overhead.

---

### E6 — NetworkMonitor polling scalability (supplementary)

- **Objective / hypothesis:** `NetworkMonitor`'s sequential per-pod polling
  (`kubectl exec <pod> -- cat /proc/net/tcp`, one pod at a time) has cycle
  time that grows with the number of monitored pods — worth quantifying
  since this session's own audit found an 8-pod cluster taking ~8–13s per
  cycle against a nominal `poll_interval=5s`.
- **Test procedure:** Deploy N ∈ {1, 2, 4, 8, 16} dummy pods (scale
  `week4/scan-targets.yaml`'s replica count), measure actual observed
  poll-cycle completion time from the `[NET]`/`[QUEUED]` log cadence at each
  N.
- **Inputs/workload:** `week4/scan-targets.yaml` scaled via `kubectl scale
  deployment scan-targets --replicas=N`.
- **Expected output:** Roughly linear growth in cycle time with N, crossing
  the nominal 5s target somewhere in the 5–10 pod range — an honest,
  documentable current-design limitation (sequential, not parallel, polling).
- **CSV to collect:** `week4/results_scalability.csv` — columns: `n_pods,
  mean_cycle_time_sec, target_interval_sec`.
- **Best visualization:** Small supplementary table only (Table 5b) — not
  worth a dedicated figure on its own, but strengthens the Overhead
  section's honesty and gives you a concrete number for the Limitations
  paragraph ("polling is sequential; parallelizing per-pod checks is future
  work").
- **Section:** Overhead (folded in as a short paragraph + Table 5b, no new
  figure needed).

---

### E7 — T1610 burst-threshold sensitivity (bonus — cut first if short on time)

- **Objective / hypothesis:** `CONNECTION_BURST_THRESHOLD=5` is an empirically
  justified operating point, not an arbitrary choice — sweeping it reveals
  the precision/recall tradeoff.
- **Test procedure:** Requires the §0 prerequisite env-var change. Sweep
  `T1610_BURST_THRESHOLD` ∈ {2,3,4,5,6,7,8,10}. At each value, run 10 real
  scan trials (`week4/simulate_t1610_scan.sh` against `scan-targets`) and 10
  benign trials (`run_benign_controls.py`'s T1610 category), recording fire
  rate for each.
- **Inputs/workload:** `attacker` → `scan-targets` (attack), `benign-worker` →
  ordinary destinations (benign control).
- **Expected output:** TP rate high and roughly flat for thresholds ≤5, FP
  rate near 0 for thresholds ≥4–5, with a visible crossover — evidence for
  why 5 is a reasonable choice rather than an arbitrary one.
- **CSV to collect:** `week4/results_t1610_sweep.csv` — columns: `threshold,
  trial_type(attack|benign), trial, fired`.
- **Best visualization:** A **precision-recall style curve** — X = recall
  (TP rate on attack trials), Y = precision (1 − FP rate on benign trials),
  one point per threshold value, chosen operating point (5) highlighted.
  This is the one place in the whole plan a classic PR/ROC-style curve
  genuinely applies, since it's the only rule with a real tunable numeric
  threshold rather than a binary match.
- **Figure title:** *"Fig. 10 — T1610 Detection Precision–Recall Tradeoff
  Across Burst-Threshold Values."*
- **Table:** Table 7 — raw sweep results.
- **Section:** Ablation Study (as design justification) or a short
  standalone "Parameter Sensitivity" subsection.

---

### E8 — Fault injection and recovery

- **Objective / hypothesis:** CAGE's resilience engineering (exponential
  backoff + degraded-state reporting in `uid_resolver.py`, graceful
  subprocess cleanup, `/api/health` staleness detection) means the system
  detects and recovers from realistic infrastructure failures rather than
  silently going blind.
- **Test procedure:** With an attack simulation running, inject three
  failures in separate runs: (1) `docker stop`/`docker start` the
  `cage-control-plane` container mid-session (apiserver outage), (2) `kill
  -9` the `TetragonConsumer`'s subprocess externally, (3) truncate/rotate the
  audit log file mid-stream. For each: record time-to-detect (via
  `/api/health`'s `stale`/`degraded` fields) and time-to-recover (next
  successful detection after the fault clears).
- **Inputs/workload:** New script `week4/inject_faults.py` orchestrating the
  above against a live `fused`-mode server; poll `/api/health` throughout.
- **Expected output:** Each fault is detected within the configured
  thresholds (`STALE_AFTER_SECONDS=90` in `server.py`; watch backoff caps at
  30s in `uid_resolver.py`), and a fresh attack fired after recovery is still
  correctly detected — proving the system doesn't need a manual restart to
  keep working.
- **CSV to collect:** none required — this one is better presented as a
  qualitative timeline than tabulated raw data (though logging
  `week4/results_fault_recovery.csv` with `fault_type, t_injected, t_detected,
  t_recovered` costs nothing extra and is worth keeping).
- **Best visualization:** A **Gantt-style timeline**, one swimlane per fault
  scenario, phases marked (normal → fault injected → degraded detected →
  service restored → detection resumed) with annotated durations. Very few
  detection papers test this; it's a strong differentiator for reviewer
  confidence in a systems venue.
- **Figure title:** *"Fig. 2 — System Recovery Timeline Under Injected
  Infrastructure Failures."*
- **Section:** A dedicated short "System Robustness" subsection, positioned
  right after Overhead and before Limitations — it's the natural bridge
  between "here's the cost" and "here's what's still open."

---

### Related-work comparison (no experiment — literature table)

- **What it is:** A qualitative feature-comparison table against the related
  systems DEMO_GUIDE.md already names (K8NTEXT, UNICORN, PACED) plus Falco
  and vanilla Tetragon, since reviewers will expect this table regardless of
  what you measure. Columns: telemetry sources used, multi-hop chain
  detection (yes/no), Kubernetes-native pod-identity correlation, live
  dashboard, false-positive mitigation approach.
- **Table:** Table 6.
- **Section:** Related Work (or the opening of Evaluation, to frame why the
  rest of the results matter).

---

## 3. Figure and table summary

**9 core figures + 1 bonus (10 total, within your 7–10 target):**

| Fig | Title | Type | From |
|---|---|---|---|
| 1 | Anatomy of a Detected Attack Chain | Timeline | E3 |
| 2 | System Recovery Timeline Under Injected Failures | Timeline (Gantt-style) | E8 |
| 3 | Detection Rate by Telemetry Source and Technique | Heatmap | E2 |
| 4 | MITRE Tactic Coverage by Telemetry Configuration | Radar | E2 |
| 5 | Per-Technique Precision/Recall/F1 | Heatmap | E1 |
| 6 | CDF of Detection Latency by Source | CDF plot | E4 |
| 7 | Latency vs. Tetragon Connection Age | Scatter + trend line | E4 |
| 8 | Effect of Episode-Scoped Dedup on Chain Detection | Line graph (comparative) | E3 |
| 9 | Resource Utilization Over Time | Stacked area / multi-line | E5 |
| 10 (bonus) | T1610 Precision–Recall vs. Burst Threshold | PR curve | E7 |

Note the deliberate variety: timeline ×2, heatmap ×2, radar ×1, CDF ×1,
scatter ×1, line ×1, stacked-area ×1, PR-curve ×1 — **zero plain bar charts**.
(`plot_graph2.py`'s existing bar chart can stay as a quick sanity-check
artifact during data collection, but shouldn't be a numbered paper figure —
everything it shows is better represented in Fig. 3/5.)

**6 core tables + 1 bonus:**

| Table | Content | Companion figure |
|---|---|---|
| 1 | Per-technique TP/FP/FN/N | Fig. 5 |
| 2 | Full ablation matrix (11×3) | Fig. 3, 4 |
| 3 | Chain correlation + dedup results | Fig. 8 |
| 4 | Latency statistics per technique/source | Fig. 6, 7 |
| 5 | Resource overhead summary (+5b scalability) | Fig. 9 |
| 6 | Related-work feature comparison | — |
| 7 (bonus) | T1610 threshold sweep raw data | Fig. 10 |

---

## 4. Person A / Person B division

### Person A — Detection Correctness & Ablation

- **Owns:** E1, E2, E3, E7 (bonus)
- **Scripts to run:**
  - `week4/run_ablation.py` (extend `TECHNIQUES` dict to all 11 first)
  - `week4/run_benign_controls.py` (extend `CATEGORIES` to all 11)
  - `week4/simulate_full_suite.sh`, individual per-chain command sequences
    extracted from it for E3
  - `week4/metrics.py`'s `MetricsCollector` (wire into a new small driver
    script, e.g. `week4/run_detection_accuracy.py`)
  - New: `week4/sweep_t1610_threshold.py` (E7, needs §0 prerequisite)
- **CSVs produced:** `results_detection_accuracy.csv`, `results_ablation_full.csv`,
  `results_chain_dedup.csv`, `results_t1610_sweep.csv`
- **Graphs produced:** Fig. 1, 3, 4, 5, 8, (10)
- **Tables produced:** Table 1, 2, 3, 6 (related-work, can split with B), (7)
- **Approximate execution order:**
  1. Extend `run_ablation.py`/`run_benign_controls.py` category lists (~1hr)
  2. E2 ablation run (330 trials × up to 60s wait each in the worst case —
     budget a full session; run overnight/unattended if possible using the
     script's existing loop, confirming mode between conditions)
  3. E1 detection-accuracy run (reuses E2's malicious-trial data where
     overlapping; only need the extra benign trials)
  4. E3 chain-dedup run (the git-history "old code" comparison is the
     highest-value/lowest-effort item here — do it early)
  5. E7 threshold sweep (only if time remains)
  6. Generate Fig. 1/3/4/5/8 + Tables 1/2/3

### Person B — Performance, Overhead, Robustness

- **Owns:** E4, E5, E6, E8
- **Scripts to run:**
  - `week4/capture_latency.py` (already widened to 60s this session)
  - New: `week4/measure_overhead.py` (E5)
  - New: `week4/measure_scalability.py` (E6, scales `scan-targets.yaml`)
  - New: `week4/inject_faults.py` (E8)
- **CSVs produced:** `results_latency.csv`, `results_latency_by_connage.csv`,
  `results_overhead.csv`, `results_scalability.csv`,
  `results_fault_recovery.csv`
- **Graphs produced:** Fig. 2, 6, 7, 9
- **Tables produced:** Table 4, 5 (+5b), and half of Table 6 (related-work
  research, split with A)
- **Approximate execution order:**
  1. E4 baseline latency (N=20 × 2 techniques) — do this *before* anything
     else touches the cluster, so connection-age is controlled (~1–2hrs
     given the wait windows)
  2. E4 connection-age sweep (fixed elapsed-time firing — needs careful
     timing, budget a focused session)
  3. E5 overhead (10–15 min continuous sampling run, can run in background
     while doing other work)
  4. E6 scalability (quick, ~30 min total across 5 pod-counts)
  5. E8 fault injection (do this last — it's the most disruptive to the
     cluster; recreate `scan-targets`/`benign-worker` afterward if needed)
  6. Generate Fig. 2/6/7/9 + Table 4/5

Both of you can start immediately in parallel — neither track blocks the
other, since both just need `ABLATION_MODE=fused python3 src/server.py`
running. Sync once at the end to jointly write Table 6 (related work) and
cross-check that Person A's E3 timestamps and Person B's E4 latency numbers
are self-consistent (same technique should show similar latency in both).

---

## 5. Results section structure (where every figure/table goes)

```
5. Evaluation
  5.1 Experimental Setup
      - Single-node kind cluster, Tetragon v1.7.0, real kubectl exec / audit
        log, trial-based methodology (N per condition stated per experiment)
      - Table 6 (related-work comparison) — frames *why* this evaluation
        matters before showing numbers

  5.2 Detection Accuracy
      - Fig. 1 (attack chain timeline) — opens with a concrete example
      - Fig. 5 + Table 1 (per-technique precision/recall/F1)
      - Fig. 8 + Table 3 (chain correlation, dedup fix validation)

  5.3 Ablation Study — Necessity of Cross-Layer Fusion
      - Fig. 3 (ablation heatmap) + Table 2
      - Fig. 4 (MITRE tactic coverage radar)
      - [bonus] Fig. 10 + Table 7 (T1610 threshold sensitivity, as design
        justification closing out this subsection)

  5.4 Performance
      - Fig. 6 (latency CDF) + Table 4
      - Fig. 7 (latency vs. connection age) — framed explicitly as an
        operational characterization, with the mitigation status (widened
        evaluation-script timeouts; root cause open) stated plainly

  5.5 Overhead
      - Fig. 9 (resource utilization over time) + Table 5
      - Table 5b (scalability) + short paragraph on sequential-polling limit

  5.6 System Robustness
      - Fig. 2 (fault-injection recovery timeline)
      - Short prose: backoff/degraded-state design, no manual restart needed

  5.7 Limitations and Threats to Validity
      - Single-node cluster; WSL2/BTF kernel dependency for T1610
      - Tetragon connection-age latency effect (cross-reference Fig. 7):
        root cause open, workaround applied to evaluation methodology
      - T1021's lack of namespace-level scope exclusion (open design question)
      - Sequential NetworkMonitor polling scalability ceiling (cross-reference
        Table 5b)
```

This ordering tells one continuous story: *here's a concrete detection →
here's proof each layer is necessary → here's what it costs in time → here's
what it costs in resources → here's proof it survives failure → here's what
we're honest is still open.* That progression — correctness, then cost, then
resilience, then honest limitations — is what reviewers read as rigor rather
than a results dump.
