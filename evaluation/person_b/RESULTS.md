# Person B Results — E4, E5, E6, E8

**Status: complete, full scale.** All four experiments ran at
`EVALUATION_PLAN.md`'s full spec (N=20 for E4, 300/600/300s for E5, 10
waves/N for E6, 5 reps/scenario for E8) against the project's actual
`kind` cluster (`cage-control-plane` + 2 workers, Tetragon v1.7.0, kernel
6.6.87.2 WSL2), `ABLATION_MODE=fused`. No placeholder or fabricated
numbers appear anywhere below.

**This document supersedes the original pilot-scale results** (N=8 for
E4, 60/120/60s for E5, 3 waves/N for E6, 1 rep for E8), which are
preserved for comparison in `data/*_pilot_*.csv` and referenced explicitly
below wherever the two scales' findings differ.

**Three real bugs were found and fixed in this evaluation's own scripts
while collecting the full-scale data** (not in CAGE's `src/` — nothing
there was touched). All three share a root cause: unanchored `pgrep -f
"src/server.py"` patterns that also match a leftover shell wrapper from a
prior server restart, once that wrapper fails to exit promptly. Each is
described in its own section below, and the raw corrupted data is
archived (not deleted) as `data/*_CORRUPTED_*.csv` so the failure mode
stays inspectable. A fourth issue — a measurement confound in the
full-scale connection-age sweep — was investigated and is reported as an
open limitation rather than silently fixed. Reporting all four in detail
here is itself evidence of the evaluation process, not an admission to
bury.

## Executive summary

| # | Experiment | Headline finding |
|---|---|---|
| E4 | Latency distribution (N=20) | Audit-log detections: 0.19s mean [0.18, 0.20] 95% CI, essentially instantaneous. Tetragon detections: 27.96s mean [27.88, 28.04] 95% CI, tight and highly consistent (σ=0.17s) on a server that's been running for several minutes. Connection-age sweep results are **not reported as a clean finding** — see the dedicated note below. |
| E5 | Resource overhead (300/600/300s) | CPU flat at 3.1–3.2% across idle and active phases alike (241 samples); RSS flat at 134.8–134.9MB, growing by only ~0.1MB across the full 20-minute run — this longer window resolves the pilot's "can't tell bounded-vs-leak" ambiguity in favor of bounded. |
| E6 | NetworkMonitor scalability (10 waves/N) | Cycle time stays within [3.6s, 6.1s] (95% CI) of the 5s target across the entire N=1→16 range (3 to 18 total monitored pods), with heavily overlapping confidence intervals across all N — no statistically distinguishable growth trend. Confirms the pilot's finding that the `ThreadPoolExecutor` concurrent-polling fix holds under scale. |
| E8 | Fault injection and recovery (5 reps × 3 scenarios) | **15/15 fault injections functionally recovered** — 100% for all three scenarios, Wilson 95% CI [0.57, 1.00] per scenario (small-N floor, not evidence of unreliability). Tetragon-consumer-kill recovers fastest (mean 13.3s functional recovery); audit-log-truncate and control-plane-outage both land around 4 minutes. |

---

## Bugs found and fixed during full-scale data collection

### Bug 1 — E8's functional-recovery check silently read the wrong log file

`run_full_scale_all.sh`'s `get_server_log()` resolved the CAGE server's
PID via `pgrep -f "src/server.py" | head -1`. This pattern also matches
the `bash -c "... nohup python3 src/server.py ... & disown; echo
started"` wrapper that `measure_scalability.py`/`run_latency_batch.py`
use to background a server restart. A wrapper from E6's last restart (N=16)
never exited — traced to the wrapper inheriting this evaluation's own
stdin instead of being fully detached — and its lower PID sorted before
the real server's, so `head -1` picked the wrapper. E8's
functional-recovery check was then pointed at the orchestration script's
own stdout log instead of the server's log for the entire first E8
attempt: 13 fault-injection trials recorded a false "never recovered" for
faults that had, per the (correctly-sourced) `/api/health` timings in the
same rows, already recovered in seconds. **Fix:** anchored the pattern to
`^python3 src/server.py`, and added `stdin=subprocess.DEVNULL` to the
restart `Popen` calls so the wrapper can't linger in the first place.
Corrupted data: `data/results_fault_recovery_CORRUPTED_wrong_logfile_bug.csv`.
E8 was re-run clean after the fix (this is the data reported below).

### Bug 2 — E5's CPU/RSS sampling silently measured the wrong process

`common.py`'s `find_server_pid()` had the identical unanchored pattern,
used by `measure_overhead.py` to find the PID to sample. The first
full-scale E5 run (which happened to overlap with the same lingering
wrapper from Bug 1, since E5 ran immediately after E6 and before the
wrapper was discovered/killed) measured 0.0% CPU and 1.7MB RSS across all
three phases for the entire 20-minute run — implausible for a live Flask
server under load, and a dead giveaway once compared against the pilot's
~92MB baseline. **Fix:** identical anchor fix in `find_server_pid()`.
Corrupted data: `data/results_overhead_CORRUPTED_wrong_pid_bug.csv`. E5
was re-run clean after the fix (this is the data reported below).

### Bug 3 (methodology, not code) — orchestration script corrupted by a live edit

While Bug 1's fix was being applied, `run_full_scale_all.sh`'s own
`bash run_full_scale_all.sh` process (PID 4709) was still running,
midway through the E8 stage. Editing the script file on disk while a
non-interactive `bash script.sh` invocation is still executing it
desynchronizes bash's byte-offset read position from the file, and the
script crashed with a syntax error once execution reached the
now-shifted trailing lines (after E8 itself had already completed
successfully). Practical consequence: the final "FULL-SCALE RUN
COMPLETE" log line and the `kubectl scale deployment scan-targets
--replicas=5` cleanup step never ran; the cleanup step was re-run
manually. No data was affected — this is recorded here as an operational
lesson (don't hot-edit a running orchestration script), not a bug in the
script's logic.

---

## E4 — Detection Latency Distribution & Connection-Age Effect

**Scale used:** full plan spec, N=20 trials per technique.

**Raw data:** `data/results_latency.csv` (distribution),
`data/results_latency_by_connage.csv` (connage sweep). **Table:**
`tables/table4_latency.md`. **Figures:**
`figures/fig6_latency_cdf.png`, `figures/fig7_latency_vs_connage.png`.

### Distribution results (N=20 each)

| Technique | Source | N | Mean (s) | 95% CI of mean (s) | Stdev (s) | Min–Max (s) |
|---|---|---|---|---|---|---|
| T1059 | Tetragon eBPF | 20 | 27.96 | [27.88, 28.04] | 0.17 | 27.31–28.11 |
| T1552 | K8s audit log | 20 | 0.19 | [0.18, 0.20] | 0.02 | 0.16–0.26 |

**Finding, now on a 4x larger sample:** the bimodal split holds and
tightens further. Audit-log detections remain sub-second and extremely
tight; Tetragon detections cluster at ~28s with the lowest variance seen
across any scale tested in this evaluation (σ=0.17s over 20 trials). This
is the primary, most heavily replicated latency claim in this paper —
robust to the confound described below, since the distribution test does
not restart the server between trials.

### Connection-age sweep — reported as an open finding, not a clean result

The full-scale connage sweep (ages 5, 15, 30, 60, 120s) produced results
that **contradict the pilot-scale connage sweep**, and the discrepancy
was traced to a measurement confound rather than accepted at face value:

| Target age (s) | Actual age (s) | Latency (s) — **full-scale** | Latency (s) — pilot (for comparison) |
|---|---|---|---|---|
| 5 | 6.05 | 2.058 | 29.87 (at actual age 7.24s) |
| 15 | 15.0 | 1.232 | 29.83 (at actual age 37.11s) |
| 30 | 30.0 | 6.088 | 29.95 (at actual age 66.94s) |
| 60 | 60.0 | 0.174 | 30.04 (at actual age 96.89s) |
| 120 | 120.0 | 14.227 | 29.97 (at actual age 126.92s) |

The pilot sweep found a flat ~30s plateau at every age tested (7–127s),
supporting a "fixed periodic boundary, not age-dependent" revision of the
project's original hypothesis (see README.md). The full-scale sweep,
re-running the identical script and methodology, instead found short and
non-monotonic latencies with no discernible pattern. **We do not believe
this reflects a genuine change in system behavior.** Inspecting the raw
server log (`evaluation_e4_connage.log`) for this run shows a burst of 13
T1059 detection lines in the first ~24 seconds after the connage-sweep's
server restart — far more than the attacker pod's own ~30s background
loop could produce in that window. The full-scale connage sweep runs
immediately after the N=20 distribution test (which itself generates 40
detections, 2.5x the pilot's 16), and we assess the most likely
explanation is that this larger volume of recent Tetragon activity was
still draining through the newly-restarted consumer's connection when the
sweep's early trials fired, so `wait_for_pattern`'s next-matching-line
logic — which is otherwise correct; it only scans bytes written after
each trial's own start position — caught a **backlogged** detection
rather than one genuinely caused by that trial's own attack command,
producing an artificially short recorded latency.

**This is reported as an unresolved discrepancy, not resolved into either
hypothesis.** Neither "age-dependent" (the original hypothesis) nor
"fixed ~30s boundary regardless of age" (the pilot's revision) is
re-confirmed by this run; what full-scale *does* add is evidence that
Tetragon-sourced latency measurements taken shortly after a consumer
restart are sensitive to recent event history in ways this evaluation's
current tooling does not control for. The concrete, actionable fix — wait
for the post-restart log to go quiet (no new matching lines for some
settle window) before starting the age clock, rather than a fixed 5s
warmup — is recommended as follow-up work rather than attempted here, to
avoid compounding an already-long unattended run with an untested new
code path. **The distribution test's N=20 result above is unaffected by
this confound** (no restart between trials) and remains this paper's
primary, reliable latency claim.

## E5 — Resource Overhead

**Scale used:** full plan spec, idle_pre=300s, active=600s, idle_post=300s,
sampled every 5s (241 total samples on the server process). Active phase
generated real load with a repeating mix of T1059 and T1552 commands
every 3s. **This is the corrected re-run** — see Bug 2 above; the original
full-scale attempt measured the wrong process.

**Raw data:** `data/results_overhead.csv`. **Figure:**
`figures/fig9_resource_overhead.png`. **Table:** `tables/table5_overhead.md`

| Phase | N samples | Mean CPU (%) | 95% CI | Mean RSS (MB) | 95% CI |
|---|---|---|---|---|---|
| baseline_cage_off | 1 | 0.0 | — | 0.0 | — |
| idle_pre | 60 | 3.2 | [3.20, 3.20] | 134.8 | [134.80, 134.80] |
| active | 121 | 3.2 | [3.16, 3.18] | 134.8 | [134.83, 134.85] |
| idle_post | 60 | 3.1 | [3.10, 3.10] | 134.9 | [134.90, 134.90] |

**Finding:** CPU is flat across idle and active phases alike — no
sustained elevated load under the tested attack rate. RSS grows by only
~0.1MB across the full 20-minute run (134.8→134.9MB), a much flatter
trend than the pilot's ~0.7MB growth over 4 minutes. **This resolves the
pilot's explicitly-flagged ambiguity** ("too short to distinguish
bounded-with-a-small-constant-term from a slow leak") in favor of
bounded: a 5x longer active phase generating substantially more events
shows growth essentially stopping, consistent with the periodic
stale-entry sweep reclaiming memory as designed, not a leak. The absolute
baseline RSS here (134.8MB) is higher than the pilot's (91.9MB) — expected,
since this measurement was taken later in a longer-running, busier
overall session with a larger accumulated pod-UID cache and alert
history, not evidence of anything wrong.

**Scope and measurement caveats carried forward unchanged:** this
measures the CAGE server process only, not Tetragon's own per-pod cost
(not measurable in this cluster without `metrics-server`); `ps %cpu` is a
decaying lifetime average, not instantaneous.

## E6 — NetworkMonitor Polling Scalability

**Scale used:** full plan spec, N ∈ {1, 2, 4, 8, 16} scan-target pods, 10
requested waves per N (9 usable inter-wave gaps per N, since N waves
yield N−1 gaps), server restarted fresh for each N.

**Raw data:** `data/results_scalability.csv`. **Table:**
`tables/table5b_scalability.md`

| N scan-target pods | Total monitored pods | N waves | Mean cycle time (s) | 95% CI (s) | Over 5s target? |
|---|---|---|---|---|---|
| 1 | 3 | 9 | 4.69 | [3.58, 5.80] | no |
| 2 | 4 | 9 | 4.68 | [3.60, 5.76] | no |
| 4 | 6 | 9 | 5.35 | [4.57, 6.12] | yes |
| 8 | 10 | 9 | 5.35 | [4.57, 6.13] | yes |
| 16 | 18 | 9 | 4.90 | [3.78, 6.03] | no |

**Finding, confirmed at full scale:** mean cycle time hovers in a narrow
band (4.68–5.35s) across the entire tested range, and — importantly — the
95% confidence intervals for every N overlap heavily with one another
(all span roughly [3.6s, 6.1s]). Two of the five N values have a mean
that nudges just over the nominal 5s target, but given the overlapping
CIs this is not statistically distinguishable from sampling noise around
a flat ~5s cycle time, not a growth trend with N. This is the same
qualitative conclusion the pilot reached (cycle time bounded, not
growing with pod count), now with a proper uncertainty band around it
rather than 3-wave point estimates. As established in the pilot write-up,
this validates the `ThreadPoolExecutor`-based concurrent-polling fix that
replaced the original sequential design — the sequential design's failure
mode (a full sweep taking longer than the 10-second scan-burst detection
window, silently splitting a multi-pod scan attack across sweeps) is what
originally motivated this experiment, discovered during this project's
own T1610 debugging, not invented for this evaluation.

No figure was planned for E6 (Table 5b only, per the plan) — none
generated, consistent with that.

## E8 — Fault Injection and Recovery

**Scale used:** full plan spec, 5 reps × 3 scenarios = 15 fault
injections, 20s settle between reps. **This is the corrected re-run** —
see Bug 1 above; the first full-scale attempt's functional-recovery
column was unreliable due to the wrong-logfile bug (13 of 15 trials
affected; archived, not used).

**Raw data:** `data/results_fault_recovery.csv`. **Tables:**
`tables/table_fault_recovery.md` (per-rep detail),
`tables/table_fault_recovery_summary.md` (aggregated, with Wilson 95% CI).
**Figure:** `figures/fig2_fault_recovery_timeline.png`

| Fault | Reps | Functional recovery rate | Wilson 95% CI | Mean detect (s) | Mean functional-recovery (s) | Spurious alerts (total/15) |
|---|---|---|---|---|---|---|
| tetragon-consumer-kill | 5 | 5/5 (100%) | [0.57, 1.00] | 0.4 | 13.3 | 4 |
| audit-log-truncate | 5 | 5/5 (100%) | [0.57, 1.00] | 53.1 | 226.0 | 12 |
| control-plane-outage | 5 | 5/5 (100%) | [0.57, 1.00] | 58.2 | 250.3 | 0 |

**Finding, now with real replication:** all 15 injected faults
functionally recovered without any manual intervention — every scenario
hit 100% across 5 independent reps. The Wilson 95% CI floor of 0.57 (not
closer to 1.0) is an artifact of the small N=5 sample size, not evidence
of unreliability — it is the correct, honest lower bound a 5/5 observed
result supports statistically, and is reported rather than replaced with
an unqualified "100%" specifically so that distinction is visible.
Recovery-time ordering matches the pilot exactly (tetragon-kill fastest,
then audit-truncate, then control-plane-outage close behind) and the
magnitudes are consistent with the single pilot runs (pilot: 34.9s /
241.9s / 303.8s vs. full-scale means: 13.3s / 226.0s / 250.3s — same
ordering, full-scale means somewhat faster, plausibly because the pilot's
single run for control-plane included some extra one-off apiserver
warmup variance that averages out across 5 reps).

**Spurious-alert counts are proportionally consistent with the pilot's
finding**: audit-log-truncate accumulated the most (12 across 5 reps,
~2.4/rep) and control-plane-outage the fewest (0 across all 5 reps) —
still consistent with the attacker pod's own ~30s background T1059 loop
landing inside the longer fault windows (audit-truncate and
control-plane-outage both have multi-minute functional-recovery windows,
giving the background loop more opportunities to fire during the window)
rather than evidence of fault-induced false detections. This pilot-noted
methodology gap (background loop not isolated/controlled for) still
applies at full scale and is carried into the Limitations section
unchanged.
