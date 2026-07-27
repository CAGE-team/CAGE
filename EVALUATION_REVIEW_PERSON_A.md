# EVALUATION_REVIEW.md — Sufficiency Review of EVALUATION_PLAN.md for IEEE Journal Submission

This document is a critique, not a replacement. `EVALUATION_PLAN.md` is
untouched. Everything below either (a) strengthens an experiment already in
that plan, or (b) adds a genuinely new one that a rigorous IEEE
systems/security reviewer would ask about if it were missing. Nothing here is
padding for its own sake — every addition is justified against a specific,
named reviewer concern.

## Verdict

**The original plan is a strong foundation but not yet sufficient for a
journal-level submission as written.** It correctly covers detection
accuracy, ablation, latency, overhead, and fault tolerance — that's more
rigor than most workshop papers bother with. What it's missing are the four
things a *journal* reviewer (as opposed to a demo audience) specifically
checks for in a security-detection paper:

1. **Statistical confidence.** Every detection-rate number in the plan is a
   raw percentage from N=10–15 trials. A reviewer will immediately ask: is
   "10/10 = 100%" actually distinguishable from "9/10 = 90%" at that sample
   size, or is it noise? Raw percentages without confidence intervals are a
   very common desk-reject-adjacent criticism for exactly this kind of paper.
2. **Adversarial evasion.** The paper already has a strong, specific story
   about removing a name-based whitelist because it was a detection bypass.
   That story is incomplete without actually testing whether an attacker who
   *knows* the current thresholds (burst=5, fork-bomb=25, RBAC-discovery=10,
   120s correlation window) can stay just under them and evade detection. A
   security reviewer will ask this question if the paper doesn't answer it
   first.
3. **Scalability beyond one component.** E6 only measures `NetworkMonitor`'s
   own polling cycle. It doesn't measure whether *detection itself* — latency,
   accuracy — degrades as the cluster gets busier. That's the scalability
   claim a reviewer actually cares about.
4. **No explicit threat model.** The plan is all experiments, no stated
   assumptions. A security systems paper without an explicit "here's what
   we defend against, here's what's out of scope" statement invites reviewers
   to assume the worst about what's *not* covered.

Two smaller things round this out: the resource-overhead soak test (20–30
minutes) is short for a "no leak" claim in a journal venue, and there's no
explicit reproducibility statement, which IEEE venues increasingly expect
even without a formal artifact-evaluation track.

Nothing in the original plan is unnecessary or should be cut outright. One
figure (Fig. 4, the MITRE radar) is flagged below as the first thing to drop
if the team runs short on time — it's good but the most redundant with
Fig. 3.

---

## Gap 1 — Statistical confidence intervals (applies to E1, E2, E3, E7)

**Why a reviewer flags this:** claiming "100% detection" from 10 trials is a
red flag by itself — the true underlying rate could plausibly be anywhere
from ~74% to 100% at that sample size, and reporting a bare percentage hides
that. This is the single most common statistical criticism of small-N
security-detection evaluations.

**Fix:** report a **Wilson score 95% confidence interval** alongside every
detection-rate percentage (Wilson, not the normal-approximation interval —
it stays well-behaved at N=10–15 and when the observed rate is 100% or 0%,
which the normal approximation does not). This is a closed-form calculation,
not a new experiment — apply it to E1, E2, E3, and E7's existing data.
Where feasible, also bump N from 10–15 to 20–30 for the headline claims
(full-chain detection, per-technique recall) specifically because tighter
CIs are worth the extra trials for the numbers that anchor the abstract.

**Where it shows up:** an extra pair of columns (`ci_low`, `ci_high`) in
Tables 1, 2, 3, and 7 — no new figures needed, this strengthens existing ones.

---

## Gap 2 — Evasion resistance (new experiment, E9)

**Why a reviewer flags this:** CAGE's own design history *is* an evasion
story — the pod-name whitelist was removed specifically because "an attacker
could name their pod `legitimate-app-evil` and dodge detection." A reviewer
who reads that will immediately ask: what about the numeric thresholds that
are still there? Can an attacker who knows `CONNECTION_BURST_THRESHOLD=5`
just do 4 connections? Can they know `FORK_BOMB_EXEC_THRESHOLD=25` and do 24?
Can they spread a chain's hops more than 120 seconds apart? Not testing this
leaves the paper's own stated threat model half-addressed.

- **Objective:** characterize CAGE's detection boundary against an attacker
  who deliberately stays just under each known, static threshold.
- **Procedure:** for each tunable threshold, run the attack at
  `threshold − 1` (just under, should evade) and `threshold` (right at it,
  should detect) — T1610 burst at 4 vs. 5 connections, T1499 fork-bomb at 24
  vs. 25 execs, T1613 RBAC discovery at 9 vs. 10 reads in 30s, and a full
  attack chain with hops spread 130s apart (outside the 120s window) vs. 90s
  apart (inside it). 10 trials per boundary condition.
- **Inputs:** `attacker` pod, deliberately tuned versions of the existing
  attack commands (e.g. `simulate_t1610_scan.sh`'s loop capped at 4 targets
  instead of 5).
- **Expected output:** confirms the boundary behaves exactly as the threshold
  constants say it should — at-threshold detects, just-under evades. This is
  not a failure to report defensively; it's the honest, precise
  characterization of where the line is, which is exactly what a security
  paper is supposed to state explicitly rather than leave implicit.
- **CSV:** `results_evasion.csv` — columns: `technique, boundary_condition
  (just_under|at_threshold), threshold_value, trial, fired`.
- **Visualization:** don't give this its own figure — merge it as a second
  panel into the existing T1610 threshold-sensitivity figure (E7), which
  already plots the same underlying tradeoff. **Fig. 10 becomes a two-panel
  figure:** (a) the existing PR-style curve across the full threshold sweep,
  (b) a compact dot/lollipop plot marking exactly where the at-threshold vs.
  just-under points fall for all four tested boundaries (T1610, T1499,
  T1613, correlation window — the last one only if Gap 3's prerequisite is
  approved). This keeps the figure count controlled while genuinely adding
  the analysis.
- **Table:** extends Table 7 (now "Parameter Sensitivity & Evasion Boundary
  Results") with the new boundary rows.
- **Section:** Ablation Study, as a "Design Justification & Evasion
  Boundary" closing subsection — pairs naturally with the threshold sweep
  that's already there.

---

## Gap 3 — Correlation-window (120s) sensitivity — flagged, needs your approval

**Why it matters:** the 120-second chain-correlation window is arguably the
single most consequential tunable parameter in the whole system — it governs
*all 5* CRITICAL chains, not just one technique. It currently isn't tested
at any value other than 120s. A reviewer will ask why 120s specifically, and
right now there's no data to answer that.

**Why it's not in the ready-to-run script set:** unlike
`CONNECTION_BURST_THRESHOLD` (a clean module-level constant I can override
at runtime without touching source), the 120-second window is a **hardcoded
inline literal** — `timedelta(seconds=120)` appears twice in
`src/causal_graph.py` (in `_sweep_stale_pods` and in the event-window prune
inside `add_event`). There is no way to sweep it without either editing
those two lines or monkey-patching `timedelta` itself (which is fragile and
not something I'll do). Per your instruction not to modify existing project
files without a verified bug to fix, I have **not** made this change.

**Recommended change, for your explicit sign-off before running E10:**

```python
# src/causal_graph.py — add near the other named constants (~line 46)
import os
CORRELATION_WINDOW_SECONDS = int(os.environ.get("CAGE_CORRELATION_WINDOW", "120"))
```
then replace both `timedelta(seconds=120)` occurrences with
`timedelta(seconds=CORRELATION_WINDOW_SECONDS)`. Behavior-preserving at the
default (120), identical pattern to the T1610 threshold override already
proposed in `EVALUATION_PLAN.md` §0.

Script `evaluation/person_a/scripts/run_window_sensitivity.py` (included in
the new evaluation folder) is written and ready to run the moment this
change is approved and applied — I'm not blocking on it, just not applying
it unilaterally.

- **Objective:** show chain-detection recall vs. window size, and
  (importantly) the false-chain-correlation rate at large window sizes —
  a window that's too generous risks correlating two genuinely unrelated
  incidents on the same long-lived pod into a fabricated chain.
- **Table:** Table 7 gains a `correlation_window` variant section once run.
- **Section:** same Ablation "Design Justification" subsection as Gap 2.

---

## Gap 4 — Broader scalability (new experiment, E11, subsumes old E6)

**Why a reviewer flags this:** "scalability" in a systems paper means "does
the *system's core function* hold up under load," not "does one internal
polling loop stay on schedule." The original E6 only measures the latter.

- **Objective:** characterize whether detection latency and accuracy degrade
  as ambient cluster activity increases — the realistic scaling question.
- **Procedure:** deploy background "noise" pods (reuse `benign-app.yaml`'s
  pattern) at N ∈ {0, 10, 25, 50} in addition to the existing test pods, each
  doing light periodic activity (a cron-like innocuous exec every few
  seconds) to generate ambient telemetry volume. At each N, re-run a small
  T1059/T1552 latency probe (reusing E4's method) and record latency
  alongside `/api/health`'s `queue_size`. Fold the *existing* E6
  (NetworkMonitor cycle time vs. monitored pod count) in as a second panel of
  the same figure — they're both "how does the system behave as N grows"
  and belong together rather than as a lone supplementary table.
- **Expected output:** latency degrades gracefully (or doesn't) as N grows;
  `queue_size` growth (if any) directly shows whether the correlator is
  keeping up — ties back to this session's own finding that the Tetragon
  delivery pipe can lag under load.
- **CSV:** `results_scalability.csv` — columns: `n_background_pods,
  mean_latency_sec, queue_size_p95, poll_cycle_time_sec`.
- **Visualization:** **Fig. 11**, two panels: (a) detection latency vs.
  background pod count (line graph), (b) `NetworkMonitor` poll-cycle time vs.
  monitored pod count (line graph, the original E6 data) — a genuine
  scalability figure instead of a footnote table.
- **Table:** Table 8 — raw scalability data backing both panels.
- **Section:** Overhead (renamed "Overhead & Scalability" if this subsection
  grows enough to warrant the split).

---

## Gap 5 — Threat model and assumptions (non-experimental, paper text)

**Why a reviewer flags this:** without an explicit scope statement, a
security reviewer will assume the paper is claiming to defend against
*everything* and will list attacks it doesn't handle as "missing" — even
ones that were never in scope. An explicit threat model heads this off.
I've drafted one in `evaluation/person_a/THREAT_MODEL_DRAFT.md`, grounded in
what this codebase actually assumes (Tetragon/eBPF and the K8s API server
are trusted; single-node `kind` cluster; no defense against a kernel-level
rootkit blinding eBPF itself; audit-log tampering by a control-plane-level
attacker is out of scope). This is text for you to review and adapt into the
paper, not something requiring experiments.

## Gap 6 — Reproducibility statement (non-experimental, paper text)

IEEE venues increasingly expect an explicit reproducibility statement even
without a formal artifact track. Drafted in
`evaluation/person_a/REPRODUCIBILITY_CHECKLIST.md` — exact software versions
(Tetragon v1.7.0, kind, kubectl, Python/library versions — fill in from your
actual environment), hardware spec placeholders, and the exact command
sequence to reproduce each table from a clean cluster.

## Gap 7 — Extend E5's overhead soak duration

20–30 minutes is thin evidence for a "no memory leak" claim aimed at a
journal audience. Recommend extending phase 2 (active load) to at least
2 hours of repeated attack simulation for the final run — cheap to do
(the script just needs to run longer unattended), and meaningfully
strengthens the periodic-sweep-fix validation story. No structural change to
E5, just a duration recommendation — noted in the new folder's README.

## Gap 8 — Severity-stratified accuracy breakdown

Cheap addition, no new experiment: CAGE assigns LOW/MEDIUM/HIGH/CRITICAL
severities, but E1/E2/E3 as specified don't break results down by severity
class. Worth one extra cut of already-collected data — are CRITICAL chain
detections more reliable than individual LOW-severity alerts? Added as an
optional extra column/grouping in the `run_detection_accuracy.py` script's
output rather than a new CSV.

---

## Gap 9 — `run_ablation.py`'s existing T1610 test is currently broken

Found while building Person A's scripts, worth flagging explicitly since it
would otherwise silently corrupt E2's results if the team reused this file
as-is. `run_ablation.py`'s `TECHNIQUES["T1610"]` is:

```python
'kubectl exec attacker -- bash -c "timeout 2 bash -c \\"echo > /dev/tcp/10.244.2.3/80\\""'
```

Two independent problems: (1) it targets a hardcoded, cluster-specific IP
that is very likely stale; (2) even if the IP were valid, it's a **single**
connection attempt, and `_check_t1610` has required a 5-distinct-destination
burst within 10 seconds since the burst-threshold fix earlier this project's
history — a single connection cannot satisfy that condition regardless of
whether it lands on a real pod. Run as-is today, this entry would report
0/10 under every ablation condition, indistinguishable from a genuine
detection gap.

Per your instruction not to modify existing files without a verified bug to
fix, `run_ablation.py` has **not** been changed. `run_ablation_full.py` in
the new evaluation folder uses the correct burst pattern instead (the same
`scan-targets` multi-destination approach already proven working in
`simulate_full_suite.sh`/`simulate_t1610_scan.sh`). Recommend fixing
`run_ablation.py`'s entry directly at some point since anyone running it
standalone will hit the same issue — flagging rather than fixing
unilaterally, since it's outside this task's scope of "Person A's new work."

---

## Finalized figure and table list (supersedes the count in EVALUATION_PLAN.md §3)

**11 core figures** (composited where it keeps the count controlled instead
of proliferating near-duplicate figures):

| Fig | Title | Type | Status |
|---|---|---|---|
| 1 | Anatomy of a Detected Attack Chain | Timeline | unchanged |
| 2 | System Recovery Timeline Under Injected Failures | Timeline | unchanged |
| 3 | Detection Rate by Telemetry Source and Technique | Heatmap | unchanged |
| 4 | MITRE Tactic Coverage by Telemetry Configuration | Radar | unchanged — **first to cut under time pressure** |
| 5 | Per-Technique Precision/Recall/F1 (with 95% CI) | Heatmap | enhanced (Gap 1) |
| 6 | CDF of Detection Latency by Source | CDF plot | unchanged |
| 7 | Latency vs. Tetragon Connection Age | Scatter + trend | unchanged |
| 8 | Effect of Episode-Scoped Dedup on Chain Detection | Line graph | unchanged |
| 9 | Resource Utilization Over Time (extended soak) | Stacked area | enhanced (Gap 7) |
| 10 | Parameter Sensitivity & Evasion Boundary (2-panel) | PR curve + lollipop | expanded (Gap 2) |
| 11 | Scalability: Latency & Poll-Cycle vs. Load (2-panel) | Line graph ×2 | expanded (Gap 4) |

Bonus, run only if Gap 3's prerequisite is approved: window-sensitivity data
folds into Fig. 10/Table 7 as an additional series, no new figure number
needed.

**8 core tables:**

| Table | Content | Change |
|---|---|---|
| 1 | Per-technique TP/FP/FN/N + 95% CI | + CI columns (Gap 1) |
| 2 | Full ablation matrix (11×3) + 95% CI | + CI columns (Gap 1) |
| 3 | Chain correlation + dedup results + 95% CI | + CI columns (Gap 1) |
| 4 | Latency statistics per technique/source | unchanged |
| 5 | Resource overhead summary (extended soak) | duration noted (Gap 7) |
| 6 | Related-work feature comparison | unchanged |
| 7 | Parameter sensitivity + evasion boundary raw data | merged E7+E9(+E10) |
| 8 | Scalability raw data (latency + poll-cycle vs. load) | merged E6+E11 |

---

## Updated Person A scope

Gaps 1, 2, 3(prep), 5, 6, 8 all land on Person A's side (they're extensions
of E1/E2/E3/E7, or paper-text deliverables) — this is reflected in the new
`evaluation/person_a/` folder built alongside this review. Person B's E4/E5/
E6/E8 gain Gap 4 (E11, scalability) and Gap 7 (extended soak duration) —
noted here for when Person B's folder is built, not built now per your
instruction to complete Person A's work only.
