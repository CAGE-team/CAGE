# CAGE: A Cross-Layer Attack Graph Engine for Real-Time Kubernetes Runtime Security

**Status of this draft:** Working manuscript draft, assembled from the
completed Person B evaluation (systems/performance: E4 latency, E5
resource overhead, E6 polling scalability, E8 fault tolerance) plus the
related-work comparison (Table 6). Sections owned by Person A (detection
accuracy E1, ablation E2, chain-correlation E3, threshold sensitivity E7)
are marked `[PERSON A — PENDING]` below with the exact structure her
completed data should slot into — nothing in her scope has been started,
duplicated, or guessed at here. **All Person-B numbers below are now
full scale** (N=20 for E4, 300/600/300s for E5, 10 waves/N for E6, 5
reps/scenario for E8), sourced from `evaluation/person_b/RESULTS.md`,
which is the authoritative, more detailed version of everything
summarized here — including three real bugs found and fixed in this
evaluation's own scripts during full-scale data collection (two silently
corrupted E5/E8 data via a stale-process PID ambiguity, now fixed and
re-run clean; one is an unresolved measurement confound in the
connection-age sweep, reported honestly rather than papered over). See
`RESULTS.md`'s "Bugs found and fixed" section for full detail before
citing any single number from this draft in isolation.

---

## Abstract

Kubernetes runtime security tools today are largely single-source: eBPF
tracers observe process, network, and capability events but cannot see
Kubernetes control-plane actions (RBAC changes, `kubectl exec` sessions,
secret reads via the API server); audit-log-based tools see control-plane
actions but are blind to what happens *inside* a container once a
connection is established. This split allows multi-stage attacks that
cross both layers — e.g., a remote exec that spawns a shell that then
exfiltrates a secret — to be only partially visible to any single-source
tool, with no way to link the partial observations into one causal chain.
We present CAGE, a cross-layer attack graph engine that fuses Tetragon
eBPF telemetry and Kubernetes audit-log events into a single causal graph,
using Kubernetes pod UID as an explicit, first-class correlation key
across both sources. CAGE detects 11 MITRE ATT&CK techniques spanning
both telemetry sources and correlates them into 5 documented multi-hop
attack chains in real time, exposed through a live dashboard. We evaluate
CAGE along two axes: detection quality (per-technique accuracy, ablation
of each telemetry source, chain-correlation precision/recall, threshold
sensitivity — `[PERSON A — PENDING]`) and systems characteristics
(end-to-end detection latency, resource overhead, monitoring-subsystem
scalability, and fault tolerance under injected infrastructure failures).
On the systems side, CAGE detects audit-log-sourced techniques in a mean
0.19s and eBPF-sourced techniques in a mean 27.96s (N=20 trials each,
95% CIs within ±0.1s of the mean for both), imposes a flat ~3.2% CPU and
~135MB RSS overhead regardless of load (300/600/300s idle/active/idle
measurement), keeps its pod-monitoring subsystem's cycle time within a
narrow band of its 5-second target across a 1-to-16 scan-target-pod
range with no statistically distinguishable growth, and functionally
recovers from all three tested classes of infrastructure fault in 15/15
injected trials. [Abstract to be finalized with Person A's headline
numbers once E1-E3/E7 complete.]

---

## I. Introduction

Kubernetes has become the dominant deployment substrate for containerized
workloads, and with that adoption has come a corresponding rise in
Kubernetes-specific attack techniques: credential theft via the metadata
or secrets API, lateral movement between pods on the same node or across
the pod network, privilege escalation through misconfigured RBAC or
dangerous container capabilities, and container escape. Detecting these
attacks well requires visibility at two structurally different layers.
**Kernel-level telemetry** (via eBPF) sees what a process actually does
once it is running inside a container — spawning a shell, opening a TCP
connection, invoking a dangerous syscall — but has no native concept of a
Kubernetes API action; a `kubectl exec` or a secret read via the API
server produces no distinguishing kernel event of its own.
**Control-plane telemetry** (the Kubernetes audit log) sees every API
action with full RBAC and identity context, but is blind to what happens
after a connection is established inside a container — it cannot see a
shell being spawned or a lateral network connection between two pods.

A single-source tool is therefore structurally unable to observe a
multi-stage attack that crosses this boundary. Consider a realistic
attack chain: an attacker uses `kubectl exec` (a control-plane action,
invisible to eBPF) to gain a shell in a pod (a kernel action, invisible to
the audit log), then reads a Kubernetes Secret via the API from inside
that shell (a control-plane action again). An eBPF-only tool sees the
shell but not the exec or the secret read; an audit-log-only tool sees
the exec and the secret read but not the shell in between, and — critically
— has no way to know the exec and the secret access are part of the
*same* causal sequence rather than two unrelated events. Correlating them
requires a source-independent identity to join on.

CAGE addresses this by using the Kubernetes pod UID — resolved once via
the Kubernetes watch API and cached, not assumed or hardcoded per
pod-name or namespace — as an explicit correlation key across both the
Tetragon eBPF stream and the Kubernetes audit log stream. Events from
either source that share a pod UID are linked in a single causal graph;
sequences of technique detections that match one of five documented
multi-hop attack patterns are escalated to a CRITICAL correlated-chain
alert, distinct from and stronger evidence than any of the individual
per-technique alerts on their own.

This paper makes the following contributions:

1. A cross-layer correlation design that uses Kubernetes pod UID (not
   pod name, not namespace, not IP address) as the join key between eBPF
   and audit-log telemetry, avoiding the false-positive and evasion risks
   of name- or label-based correlation (§III, §VI).
2. An open evaluation of both detection quality (`[PERSON A — PENDING]`)
   and systems characteristics — detection latency, resource overhead,
   monitoring-subsystem scalability under increasing pod count, and
   functional recovery from injected infrastructure faults — reported
   with statistical confidence intervals, not point estimates alone
   (§V).
3. Two systems findings that revise or validate specific design
   decisions rather than merely characterizing performance: (a) a
   ~28-second Tetragon-sourced detection latency plateau, highly
   consistent across N=20 replicated trials (σ=0.17s) — whether this
   plateau depends on connection age remains an open question: two
   independent connection-age sweeps at different scales produced
   contradictory results, and we report both plus the measurement
   confound we traced the discrepancy to, rather than asserting either
   answer (§V-D); and (b) direct evidence that a
   `ThreadPoolExecutor`-based concurrent-polling fix to the pod-to-pod
   network monitor holds cycle time flat (95% CIs overlapping across the
   entire tested range) across the tested pod-count range, where the
   original sequential design would have grown linearly and — as
   independently discovered during this project's own T1610 debugging —
   could silently split a single scan-burst attack across two polling
   cycles and evade detection entirely (§V-F).
4. An honest, explicitly scoped limitations analysis covering
   environment generalizability, attack-script realism, adversarial
   evasion testing, and statistical power, rather than a limitations
   section confined to acknowledged-but-unaddressed future work (§VI).

---

## II. Related Work

`[PERSON A — PENDING: cite and briefly describe K8NTEXT, UNICORN, PACED,
P4Control, Falco, and vanilla Tetragon in prose here, 1-2 sentences each,
matching the columns already established in Table 6 below. This prose
section is the natural home for the citations; Table 6 is the structured
comparison.]`

**Table 6** (`evaluation/person_b/tables/table6_related_work.md`)
summarizes the comparison along five axes: telemetry sources, multi-hop
chain detection, Kubernetes pod-identity correlation, live attack-graph
visualization, and false-positive mitigation strategy. It is explicitly
a **qualitative** comparison against published system descriptions, not a
quantitative benchmark — no other tool was run against CAGE's own attack
set in this project's cluster. The single highest-value quantitative
addition identified for a future revision is a head-to-head run of
vanilla Tetragon (CAGE's own eBPF backend, already present in this
project's infrastructure) against the same attack set used in E1/E2, to
produce a directly comparable precision/recall/latency baseline — this
depends on the `ABLATION_MODE=tetragon_only` infrastructure Person A's E2
experiment already owns, so it was deliberately not attempted in this
pass to avoid duplicating that work.

*(Table 6 content is maintained in
`evaluation/person_b/tables/table6_related_work.md` and should be
transcluded/pasted here verbatim at final assembly, not retyped.)*

---

## III. System Design

CAGE is a single-process Python service that consumes two independent
event streams and fuses them into one causal graph, exposed through a
Flask/SSE server and a live browser dashboard.

**Telemetry sources.**
- A **Tetragon eBPF consumer** streams process-execution, network
  (`tcp_connect`), and Linux-capability events from Tetragon's `tetra
  getevents` gRPC-backed CLI stream, filtered by two custom
  `TracingPolicy` resources (`tcp-connect-policy.yaml` for T1610,
  `capability-check-policy.yaml` for T1611/T1548).
- A **Kubernetes audit-log consumer** tails the API server's audit log
  (`tail -F --retry`, tolerant of both rotation and truncation) for
  control-plane actions: `kubectl exec` sessions, Secret reads,
  privileged-pod creation, and cluster-admin/wildcard RBAC grants.
- A **pod UID cache**, populated via the Kubernetes watch API, is the
  correlation key shared by both consumers above — every event from
  either source is tagged with the pod UID it belongs to before being
  handed to the causal graph, which is what makes cross-source
  correlation possible without assuming stable pod names or IP
  addresses (both of which change across pod restarts and are also
  attacker-influenceable in ways a cluster-assigned UID is not).
- A **pod-to-pod network monitor** independently polls scan-target pods
  for new outbound TCP connections (concurrent, `ThreadPoolExecutor`-based
  polling — see §V-F for why this replaced an earlier sequential design)
  as a complementary signal to the Tetragon `tcp_connect` kprobe path.

**Detection.** CAGE currently detects 11 MITRE ATT&CK techniques:

| Technique | Behavior | Severity | Source |
|---|---|---|---|
| T1059 | Shell spawned inside a pod | MEDIUM | Tetragon eBPF |
| T1021 | Remote exec (`kubectl exec`) | MEDIUM | K8s audit log |
| T1610 | Pod-to-pod network lateral movement (scan-burst) | MEDIUM | Tetragon kprobe + NetworkMonitor |
| T1552 | Secret access via K8s API | HIGH | K8s audit log |
| T1611 | Container escape (dangerous capability / escape binary) | HIGH | Tetragon eBPF |
| T1548 | Privilege escalation attempt inside a container | HIGH | Tetragon eBPF |
| T1548-PRIV-POD | Privileged pod created | HIGH | K8s audit log |
| T1548.005 | Cluster-admin / wildcard RBAC grant | CRITICAL | K8s audit log |
| T1496 | Cryptomining process signature | HIGH | Tetragon eBPF |
| T1499 | Fork-bomb-like exec burst (resource DoS) | HIGH | Tetragon eBPF |
| T1613 | RBAC / resource discovery burst | MEDIUM | K8s audit log |

Five multi-hop sequences of these are escalated to a CRITICAL correlated
chain alert when they occur on the same pod UID within a 120-second
correlation window: T1059→T1552, T1021→T1059→T1552, T1059→T1610→T1552,
T1059→T1548→T1611, and T1611→T1552.

**Scope-exclusion design.** Every behavioral rule except T1021 (§VI)
excludes events from CAGE's own namespace-scoped infrastructure by
namespace, not by pod name — a name-based exclusion list was found during
development to be a real evasion vector (an attacker able to name or
rename a pod to match an excluded name could suppress detection of their
own activity) and was removed in favor of the namespace-only design.

---

## IV. Evaluation Methodology

**Environment.** All experiments (both Person A's and Person B's) run
against the same `kind`-provisioned 3-node cluster (1 control-plane + 2
workers) on a single host, Tetragon v1.7.0, kernel 6.6.87.2 (WSL2, Linux
subsystem on Windows), `ABLATION_MODE=fused` (all consumers active)
unless a specific experiment (E2, or a future quantitative Table 6
baseline) deliberately varies it.

**Metrics and their definitions.** `[PERSON A — PENDING: state precise
operational definitions of true positive / false positive / false
negative for both per-technique detection (E1) and chain correlation
(E3) here — e.g., what counts as a "true positive chain" vs. a set of
individually-correct-but-unlinked per-technique alerts.]` For the
systems experiments: **detection latency** (E4) is measured
wall-clock-to-wall-clock from the attack command's issuance to the
corresponding alert line appearing in the server log; **resource
overhead** (E5) is `ps -o %cpu=,rss=` sampled every 5s on the CAGE server
process specifically (not the Tetragon agent or kube-apiserver — see the
scope note in §V-E); **cycle time** (E6) is the wall-clock gap between
consecutive full polling sweeps of the `NetworkMonitor`; **fault
recovery** (E8) distinguishes *health-flag* recovery
(`/api/health` reporting non-stale) from *functional* recovery (a real
post-fault attack is correctly detected) as two separate, both-reported
measurements, because the health flag is event-triggered and cannot by
construction prove recovery before new traffic occurs (see §V-G).

**Statistical treatment.** Continuous measurements (E4 latency, E5
CPU/RSS, E6 cycle time) are reported as mean with a 95% confidence
interval computed from the t-distribution (df = N−1), alongside median,
stdev, p95, min/max for distributional shape. E8's per-scenario
functional-recovery success rate is a binomial proportion and is reported
with a Wilson score 95% interval rather than the naive normal
approximation, which is unreliable at the small N (5 reps/scenario by
default) used here. `[PERSON A — PENDING: state the corresponding
interval choice for E1's per-technique detection-rate proportions —
Wilson score is the natural, consistent choice if not already decided.]`

**Reproducibility.** Every script referenced in this section lives under
`evaluation/person_b/scripts/` (Person B) or the corresponding Person A
location (`[PERSON A — PENDING: path]`), takes explicit CLI flags for
scale (trial counts, phase durations, replication count), and writes
timestamped raw CSVs to `evaluation/person_b/data/` that are never
overwritten silently — pilot-scale runs were archived with `_pilot_*`
suffixes before the full-scale re-run began, so both scales' raw data
remain available for inspection. `evaluation/person_b/scripts/
run_full_scale_all.sh` reproduces the full-scale Person-B run end to end,
including automatic environment-recovery retries (`restart_cage.sh`) if
any stage's server connection drops mid-run.

---

## V. Results

### A. Per-Technique Detection Accuracy (E1) `[PERSON A — PENDING]`

### B. Ablation Study — Source Contribution (E2) `[PERSON A — PENDING]`

### C. Chain Correlation Precision/Recall (E3) `[PERSON A — PENDING]`

### D. Detection Latency (E4)

**Scale:** full plan spec, N=20 trials/technique for the distribution
measurement. See `evaluation/person_b/tables/table4_latency.md` and
`evaluation/person_b/RESULTS.md` for full detail.

Detection latency is cleanly bimodal by source, and the split tightens
further at full scale. Audit-log-sourced detections (T1552) are fast and
tight: mean 0.19s, 95% CI [0.18, 0.20], across N=20 trials.
Tetragon-sourced detections (T1059) plateau at 27.96s, 95% CI [27.88,
28.04], with the lowest variance observed at any scale tested in this
evaluation (σ=0.17s across 20 trials) — not an occasional slow tail, a
highly consistent, reproducible plateau on a server that has been running
for more than a few minutes.

**Whether this plateau depends on connection age remains an open
question, reported honestly rather than resolved.** Two independent
connection-age sweeps — firing T1059 at controlled elapsed times since a
fresh server restart — were run at different scales and produced
**contradictory results**. A pilot-scale sweep (N=5 points, ages 7–127s)
found latency flat at ~29.8–30.0s at every point tested, suggesting no
age dependence (revising this project's earlier hypothesis, formed from
an isolated non-representative test, that younger connections detect
faster). A full-scale sweep using the identical script and methodology —
run immediately after the larger N=20 distribution test — instead found
short, non-monotonic latencies (0.17s–14.2s) with no discernible pattern
across the same age range. Inspecting the raw server log for this run
shows a burst of 13 T1059 detections in the 24 seconds immediately after
the sweep's server restart, consistent with a backlog of recently-queued
Tetragon events still draining through the newly-restarted consumer —
plausibly larger here because it followed a 40-detection distribution
test (2.5x the pilot's), long enough to still be draining when the
sweep's early trials fired and contaminate the position-tracking logic's
next-match search with a backlogged, not freshly-caused, detection. **We
report both sweeps' raw numbers, the log evidence for the likely
confound, and neither hypothesis as confirmed** — see
`evaluation/person_b/RESULTS.md`'s E4 section for the full comparison
table and reasoning, and §VI for the general lesson this adds to the
Limitations section. Figure 7 (`figures/fig7_latency_vs_connage.png`)
plots the full-scale sweep as measured.

An earlier attempted engineering fix based on the original age hypothesis
(periodically cycling the Tetragon consumer's subprocess connection) was
implemented and live-tested, found to introduce real event loss without
reliably reducing latency, and reverted — independent of the connage
sweep's specific findings, this remains the right call given the
reproducible cost (event loss) it demonstrated.

**Practical implication, unaffected by the connage-sweep ambiguity:**
Tetragon-sourced detections should be expected to complete in roughly 28
seconds, consistently, not near-instantaneously — established by the
N=20 distribution test, which does not restart the server between trials
and is therefore not subject to the backlog confound above. This
motivated the 60-second detection-wait timeouts used throughout this
evaluation's own scripts, and should inform any downstream consumer of
CAGE's alerts about realistic latency budgets for eBPF-sourced technique
classes specifically.

### E. Resource Overhead (E5)

**Scale:** full plan spec, idle_pre=300s / active=600s / idle_post=300s,
241 total samples. This is the corrected re-run after a stale-process PID
bug caused the first full-scale attempt to measure the wrong process
entirely (0.0% CPU / 1.7MB RSS — see RESULTS.md's "Bugs found" section);
fixed and re-run clean. See `evaluation/person_b/tables/table5_overhead.md`.

CPU usage on the CAGE server process is flat at 3.1–3.2% across idle and
active phases alike, with no visible spike under a repeating T1059+T1552
attack load every 3 seconds. RSS is flat at 134.8–134.9MB, growing by
only ~0.1MB across the full 20-minute run — this longer, full-scale
window resolves the pilot run's explicitly-flagged ambiguity ("too short
to distinguish a small bounded constant term from a slow leak") in favor
of **bounded**: a 5x longer active phase generating substantially more
events shows growth essentially stopping, consistent with the periodic
stale-entry sweep reclaiming memory as designed rather than a leak.

Overhead here is scoped to the CAGE server process only, not Tetragon's
own per-node agent cost, which this `kind`-based cluster's tooling cannot
measure without a metrics-server this evaluation did not install (see
§VI).

### F. NetworkMonitor Polling Scalability (E6)

**Scale:** full plan spec, 10 waves/N (9 usable inter-wave gaps per N).
See `evaluation/person_b/tables/table5b_scalability.md`.

`EVALUATION_PLAN.md`'s original expectation was roughly linear cycle-time
growth with monitored-pod count, crossing the nominal 5-second target
interval somewhere in the 5–10 pod range — written against
`NetworkMonitor`'s original **sequential** polling design (one `kubectl
exec` per monitored pod, one after another). That design was found not
merely slow but functionally broken during this project's own T1610
debugging: with enough monitored pods, one full sweep could take longer
than the 10-second scan-burst detection window, silently splitting a
single multi-pod scan attack across two separate sweeps so it never
accumulated enough distinct-destination events in one window to cross
the detection threshold — a false negative caused by the monitoring
subsystem's own timing, not by the detection rule itself.

The fix replaced sequential polling with a `ThreadPoolExecutor`-based
concurrent sweep, bounding cycle time by the slowest single `kubectl
exec` call rather than their sum. Full-scale data across N∈{1,2,4,8,16}
scan-target pods (3 to 18 total monitored pods, 9 waves each) shows mean
cycle time in a narrow 4.68–5.35s band across the entire tested range,
with 95% confidence intervals that overlap heavily across every N
(roughly [3.6s, 6.1s] throughout) — two of the five N values have a mean
that nudges just over the nominal 5s target, but given the overlapping
CIs this is statistically indistinguishable from noise around a flat
cycle time, not a growth trend. This is reported as direct evidence the
fix holds under scale, now with a proper uncertainty band rather than
3-wave point estimates, and the paper's framing of this subsection is
accordingly **"validating a scalability fix,"** not "characterizing a
scalability limitation" as the plan originally anticipated — a stronger
and more specific claim than the plan's own framing called for.

### G. Threshold Sensitivity (E7) `[PERSON A — PENDING]`

### H. Fault Injection and Recovery (E8)

**Scale:** full plan spec, 5 reps × 3 scenarios = 15 fault injections.
This is the corrected re-run after a stale-process PID bug pointed the
functional-recovery check at the wrong log file for the first full-scale
attempt (13 of 15 trials affected — see RESULTS.md's "Bugs found"
section); fixed and re-run clean. See
`evaluation/person_b/tables/table_fault_recovery_summary.md`.

Three infrastructure faults were injected against the live `fused`-mode
server, in ascending order of severity: (1) killing the local Tetragon
consumer's `tetra getevents` subprocess directly, testing the consumer's
own 2-second self-healing reconnect loop; (2) truncating the Kubernetes
audit log to 0 bytes in place, testing `tail -F --retry`'s truncation
handling; (3) a full `docker stop`/`start` of the `cage-control-plane`
container, simultaneously removing the API server, that node's Tetragon
agent, and the audit log file — the most severe single fault tested.

**All 15 injected faults functionally recovered without any manual
intervention — 5/5 (100%) for every scenario**, Wilson 95% CI [0.57,
1.00] per scenario. The CI's lower bound of 0.57 (rather than a value
closer to 1.0) is the correct, honest consequence of a small N=5 sample,
not evidence of unreliability, and is reported specifically so that
distinction stays visible rather than collapsing into an unqualified
"100%". Mean functional-recovery time: 13.3s for tetragon-consumer-kill,
226.0s for audit-log-truncate, 250.3s for control-plane-outage — the same
ordering the pilot's single runs found (34.9s / 241.9s / 303.8s), with
full-scale means somewhat faster, plausibly because the pilot's one-shot
control-plane run happened to include extra apiserver warmup variance
that averages out across 5 reps. None of the recovery logic exercised
here (`tetragon_consumer.py`'s 2s reconnect loop, `uid_resolver.py`'s
exponential backoff, `tail -F --retry`) was added for this experiment;
all of it is pre-existing production code.

Spurious-alert counts (4/15 windows for tetragon-kill, 12/15 for
audit-truncate, 0/15 for control-plane-outage) remain proportionally
consistent with the attacker pod's own ~30-second background T1059 loop
landing inside the longer fault windows, rather than evidence of
fault-induced false detections — audit-truncate and control-plane-outage
both have multi-minute functional-recovery windows, giving the
background loop more chances to fire during them. This pilot-noted
methodology gap (the background loop is not isolated or controlled for)
still applies at full scale and is carried into §VI unchanged; an
explicit no-background-traffic control run would close it and is
recommended as a follow-up if reviewers press on it.

A secondary finding concerns the `/api/health` staleness flag itself:
for 2 of the 3 scenarios, health-recovery could not be observed via the
flag alone, because the flag only clears on a *new* triggering event and
none was injected between fault-resolution and the deliberate
functional-recovery attack. This is why functional recovery (fire a real
attack, confirm detection), not health-flag state, is this experiment's
primary claim — a passively-updated health flag cannot, by construction,
prove recovery before something generates new traffic to trigger it.

---

## VI. Limitations and Threats to Validity

*(Full text maintained in
`evaluation/person_b/limitations_expanded.md`; summarized here by
category — transclude the full file at final assembly.)*

- **Environment scope:** single-node-host `kind` cluster inside a WSL2
  VM, not bare-metal or multi-machine Kubernetes; audit-log access
  requires apiserver-manifest patching not always available on managed
  control planes; T1610 requires a BTF-enabled kernel.
- **Virtualization-environment generalizability:** all latency/overhead
  numbers were measured inside a VM; relative findings (source-latency
  gap, bounded overhead) likely generalize, but absolute numbers — the
  ~30s Tetragon plateau specifically — may not transfer to bare metal,
  untested here.
- **Detection design scope:** T1021 has no scope exclusion at all,
  unlike every other behavioral rule (open design question, not yet
  resolved either way); the 120-second correlation window bounds how
  slow a multi-hop attack can be and still be linked into one chain
  alert.
- **Synthetic, non-adaptive attack scripts:** every attack in this
  evaluation (Person A's and Person B's alike) is a fixed, disclosed,
  non-evasive command sequence. Detection numbers characterize behavior
  against this specific, published attack set — not robustness against
  an adversary deliberately trying to evade these exact rules, which was
  not tested.
- **Limited adversarial evasion testing:** the one real evasion vector
  found and fixed during development (name-based scope exclusion) was
  found incidentally, not via systematic red-teaming; other evasion
  strategies (timing fragmentation across the correlation window, binary
  renaming) remain untested.
- **Small-sample statistical uncertainty:** trial counts are bounded by
  practical session time rather than formal power analysis; confidence
  intervals are reported throughout specifically so this uncertainty is
  visible rather than hidden behind point estimates.
- **No quantitative baseline:** Table 6 is qualitative; a head-to-head
  vanilla-Tetragon comparison (the cheapest quantitative addition,
  dependent on Person A's E2 ablation infrastructure) remains future
  work.
- **Tetragon delivery latency mechanism not conclusively root-caused:**
  the ~28s plateau (§V-D) is characterized precisely and highly
  reproducibly (N=20, σ=0.17s) but its underlying cause within Tetragon's
  own event-delivery path was not identified within this project's scope;
  an attempted fix was reverted after live testing showed it traded
  latency for event loss.
- **Connection-age dependence is an open question, not resolved:** two
  connage sweeps at different scales gave contradictory results, with
  evidence pointing to a post-restart event-backlog confound in the
  full-scale run rather than a genuine change in system behavior; neither
  the original age-dependence hypothesis nor its pilot-scale revision is
  re-confirmed (§V-D).
- **This evaluation's own measurement infrastructure had a
  reproducible failure mode**, caught and fixed during full-scale data
  collection: a stale restart-wrapper process could be silently mistaken
  for the CAGE server by substring-based `pgrep` matching, corrupting two
  full-scale measurements (E5, E8) before detection. Both were caught by
  sanity-checking against physically plausible ranges, fixed, and
  re-run — reported transparently as a property of the evaluation
  environment worth documenting for anyone extending this suite.

---

## VII. Conclusion

`[TO BE WRITTEN once Person A's results (§V-A through §V-C, §V-G) are
available — the conclusion should synthesize both the detection-quality
and systems findings together, not restate each section. Draft skeleton:
CAGE demonstrates that cross-layer correlation via pod UID closes a real
blind spot neither eBPF-only nor audit-log-only tools can see
individually [cite E2 ablation once available]; the systems evaluation
shows this correlation layer is achieved with low, flat resource cost
and functionally self-heals from realistic infrastructure faults without
manual intervention, at the cost of a characterized ~30s latency plateau
on eBPF-sourced detections specifically that deployers should plan
around.]`

---

## References

`[PERSON A / SHARED — PENDING: full reference list, including K8NTEXT,
UNICORN, PACED, P4Control, Falco, Tetragon/Cilium, and the MITRE ATT&CK
framework itself.]`

---

## Appendix: Reproducibility Artifacts

- Person B scripts, data, figures, tables: `evaluation/person_b/`
- Master full-scale re-run driver:
  `evaluation/person_b/scripts/run_full_scale_all.sh`
- Environment rebuild: `restart_cage.sh` (repo root)
- Pilot-scale raw data (archived, not deleted, for comparison):
  `evaluation/person_b/data/*_pilot_*.csv`
- Evaluation-plan review and gap analysis: `EVALUATION_REVIEW.md` (repo
  root)
