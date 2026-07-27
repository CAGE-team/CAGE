# CAGE: A Cross-Layer Attack Graph Engine for Real-Time Kubernetes Runtime Security

**Status of this draft:** Consolidated manuscript merging Person A's
detection-quality evaluation (E1 per-technique accuracy, E2 telemetry
ablation, E3 chain-correlation reliability, E9 evasion-boundary
characterization — all live-cluster, N=10) with Person B's
systems-characteristics evaluation (E4 latency, E5 resource overhead, E6
polling scalability, E8 fault tolerance — all live-cluster, full scale).
Both evaluations are now complete; nothing below is a placeholder.
Line-level copyediting for a single consistent voice throughout is the
main remaining polish pass before submission — the Abstract and
Introduction have already had a dedicated critical-review pass (citation
verification, word-count discipline); Sections III–IX are complete in
content but not yet harmonized line-by-line between the two
contributors' original drafting styles.

---

## Abstract

Kubernetes security has not kept pace with Kubernetes adoption: 89% of
organizations report at least one container- or Kubernetes-related
security incident in the past year, and newly deployed clusters can draw
their first attack probe within minutes of coming online. Existing
runtime security tools address this with a single telemetry source —
eBPF-based tracers see kernel-level process, network, and capability
events but are blind to Kubernetes control-plane actions (RBAC changes,
`kubectl exec` sessions, secret reads via the API server); audit-log
tools see every control-plane action but are blind to what happens
*inside* a container once a session or connection is established. This
split lets multi-stage attacks that cross both layers evade full
observation by either kind of tool, and prevents partial observations
from either source from being linked into one causal chain in the first
place. We present CAGE (Cross-layer Attack Graph Engine), a Kubernetes
runtime security system that fuses eBPF telemetry (via Tetragon) with
the Kubernetes audit log, using the pod UID — a value immutable for a
pod's lifetime, unlike its IP address or name — as an explicit,
first-class correlation key across both sources. CAGE detects 11 MITRE
ATT&CK techniques spanning both telemetry sources and correlates them
into five documented multi-hop attack chains in real time, exposed
through a live dashboard. We evaluate CAGE entirely on live Kubernetes
infrastructure along two axes. On detection quality: per-technique
recall reaches 100% across all 11 techniques (180 trials); a
three-condition, 330-trial ablation study reveals a perfectly
complementary telemetry split — every technique is detected with 0%
probability under one single-source configuration and 100% under the
fused one, and no single source covers more than six of the eleven,
evidencing that cross-layer fusion is structurally required, not merely
beneficial; all five attack chains re-fire reliably across ten
independent episodes each (50/50 trials); and each of CAGE's
threshold-based detectors draws a clean, disclosed line between certain
evasion and certain detection at its documented default threshold. On
systems characteristics: CAGE detects audit-log-sourced techniques in a
mean 0.19s and eBPF-sourced techniques in a highly consistent 27.96s
plateau (N=20 trials each), imposes a flat ~3.2% CPU / ~135MB RSS
overhead regardless of load, holds its pod-monitoring subsystem's cycle
time within a narrow band across a 1-to-16 scan-target-pod range with no
statistically distinguishable growth, and functionally recovers from all
three tested classes of injected infrastructure fault in 15/15 trials.
We further report multiple real detection-logic and evaluation-tooling
defects, discovered independently by both halves of this evaluation
effort, that surfaced only once each evaluation was executed against
live infrastructure rather than assessed through code review alone —
a finding with implications for how systems of this kind should be
evaluated more broadly.

**Index Terms**—Kubernetes security, eBPF, runtime intrusion detection,
audit log analysis, attack chain correlation, MITRE ATT&CK, cross-layer
telemetry fusion, cloud-native security, resource overhead, fault
tolerance.

---

## I. Introduction

Kubernetes has become the de facto standard for orchestrating
containerized workloads in cloud and enterprise environments, valued for
the scalability and operational automation it brings to deployments that
would otherwise require substantial manual effort to manage across many
nodes. That ubiquity has made Kubernetes clusters an attractive and
heavily probed target: a 2024 industry survey of 600 DevOps,
engineering, and security professionals found that 89% of organizations
had experienced at least one container- or Kubernetes-related security
incident in the preceding year, and 45% specifically reported a runtime
incident [6]. Independent honeypot research on managed Kubernetes
offerings corroborates how quickly this exposure is exploited in
practice: newly created clusters received their first attack attempt
within 18 minutes on Microsoft AKS and within 28 minutes on Amazon EKS
[7]. Detecting the techniques attackers use once inside a cluster —
credential theft via the metadata or secrets API, lateral movement
between pods, privilege escalation through misconfigured RBAC or
dangerous container capabilities, container escape — requires visibility
at two structurally different layers, and existing tooling has largely
chosen to instrument only one.

**Kernel-level telemetry** (via eBPF) sees what a process actually does
once it is running inside a container — spawning a shell, opening a TCP
connection, invoking a dangerous syscall — but has no native concept of
a Kubernetes API action; a `kubectl exec` or a secret read via the API
server produces no distinguishing kernel event of its own. Falco [1] and
Cilium Tetragon [2], two of the most widely adopted open-source runtime
security tools for Kubernetes, both instrument the kernel — via eBPF or
a kernel-module probe — and evaluate syscall- and process-level events
against a rule set, independently of any control-plane signal.
**Control-plane telemetry** (the Kubernetes audit log) sees every API
action with full RBAC and identity context, but is blind to what happens
after a connection is established inside a container — it cannot see a
shell being spawned or a lateral network connection between two pods.
K8NTEXT [3] takes this complementary approach, reconstructing the causal
structure the Kubernetes audit log otherwise scatters across thousands
of loosely linked entries — but its telemetry is the audit log alone.
Each of these tools is, within its own telemetry source, mature and
effective. None of them, by design, looks at the other source at all.

This single-source design carries a structural limitation that no amount
of tuning within one source can resolve, for two related reasons. First,
several attacker-relevant actions are observable from only one side of
the kernel/control-plane boundary: a `kubectl exec` into a pod is an
audit-log event with no kernel-level footprint of its own, while the
shell that command spawns inside the pod is a kernel-level event with no
corresponding audit-log entry. Second, and more consequentially, several
of these single-sided events are individually indistinguishable from
ordinary administrative activity. An operator's routine `kubectl exec`
into a pod to check its health looks, from the audit log alone, identical
to an attacker's remote-execution foothold; an ordinary interactive
debugging shell looks, from eBPF telemetry alone, identical to a
post-exploitation shell. Observed together and attributed to the same
workload, the sequence — remote exec, followed by a shell, followed by a
secret read from inside that shell — is a materially stronger signal
than any one event alone. But a tool that instruments only one side of
that boundary never has the opportunity to make that observation,
regardless of how well it is tuned, and critically, has no
source-independent identity to join partial observations from the other
side on even if it could see them.

Existing work has not closed this gap. Falco and Tetragon operate
exclusively on eBPF telemetry and evaluate each event independently, with
no mechanism to correlate a kernel-side event with a control-plane one.
K8NTEXT operates exclusively on the audit log, and while it reconstructs
which control-plane events a given action caused, it has no visibility
into what happened inside the pod as a result — it cannot see the shell
that a correlated `kubectl exec` spawned. PACED [4], UNICORN [5], and
P4Control [8] represent a broader provenance- and information-flow-based
school of thought that CAGE is architecturally adjacent to, but none
closes this specific gap: PACED targets a single technique family
(container escape) via kernel provenance capture; UNICORN is a
general-purpose, non-Kubernetes-specific anomaly detector built for
slow-acting APT campaigns rather than technique-level classification
against a broad catalog; and P4Control enforces information-flow policy
at the network layer via programmable switches, a different problem
(prevention via line-rate enforcement) from the after-the-fact,
technique-level detection and chain correlation this paper addresses.
None of these systems fuses eBPF telemetry with the Kubernetes audit log
through a stable, workload-level identity key to detect and correlate a
broad MITRE ATT&CK technique catalog — which is the specific gap this
paper addresses.

CAGE closes this gap by using the Kubernetes pod UID — resolved once via
the Kubernetes watch API and cached, not assumed or hardcoded per
pod-name or namespace — as an explicit correlation key across both the
Tetragon eBPF stream and the Kubernetes audit-log stream. Events from
either source that share a pod UID are linked in a single causal graph;
sequences of technique detections that match one of five documented
multi-hop attack patterns are escalated to a CRITICAL correlated-chain
alert, distinct from and stronger evidence than any of the individual
per-technique alerts on their own.

This paper evaluates CAGE along two axes, each organized around explicit
research questions and answered entirely with live-cluster trials rather
than simulation.

*Detection quality:*
- **RQ1.** What is CAGE's per-technique detection accuracy, and how does
  that accuracy differ between techniques with and without a deliberate
  scope exclusion? (§VI-A)
- **RQ2.** Does any single telemetry source achieve full detection
  coverage across CAGE's technique catalog, or is cross-layer fusion
  structurally required to do so? (§VI-B)
- **RQ3.** Does CAGE's chain correlator reliably re-detect independent
  instances of the same multi-step attack against the same workload,
  validating its episode-scoped deduplication design? (§VI-C)
- **RQ4.** For CAGE's threshold-based detectors, where exactly does the
  boundary between detection and evasion sit relative to the documented
  default thresholds? (§VI-G)

*Systems characteristics:*
- **RQ5.** What is CAGE's end-to-end detection latency, and does it
  differ systematically by telemetry source? (§VI-D)
- **RQ6.** What resource overhead does CAGE impose on its host under
  idle versus active attack load? (§VI-E)
- **RQ7.** Does CAGE's pod-to-pod network-monitoring subsystem scale
  gracefully as the number of monitored pods increases? (§VI-F)
- **RQ8.** Does CAGE functionally recover from realistic infrastructure
  faults without manual intervention? (§VI-H)

**Contributions.** The contributions of this paper are summarized as
follows:

- We present CAGE, a cross-layer runtime security architecture that
  fuses eBPF process and network telemetry with Kubernetes audit-log
  events through a live, watch-API-backed pod-identity cache, detecting
  11 MITRE ATT&CK techniques and correlating them into five documented
  multi-hop attack chains with episode-scoped deduplication (§III–IV).
- We evaluate CAGE's detection quality on live infrastructure against
  four explicit research questions, reporting per-technique detection
  accuracy with Wilson-confidence-interval-backed statistics, a
  telemetry-source ablation study, chain-correlation reliability across
  independent episodes, and an evasion-boundary characterization of the
  system's threshold-based detectors (§VI-A–C, VI-G).
- We evaluate CAGE's systems characteristics on the same live
  infrastructure, reporting detection latency, resource overhead,
  monitoring-subsystem scalability, and functional recovery from
  injected infrastructure faults, each with appropriate statistical
  confidence intervals rather than point estimates alone (§VI-D–F,
  VI-H).
- We report two systems findings that revise or validate specific design
  decisions rather than merely characterizing performance: a highly
  consistent ~28-second Tetragon-sourced detection-latency plateau whose
  dependence on connection age remains an open, honestly-reported
  question (§VI-D); and direct evidence that a concurrent-polling fix to
  the pod-to-pod network monitor holds cycle time flat across the tested
  scale range, correcting a design that could previously split a single
  scan-burst attack across two polling cycles and evade detection
  entirely (§VI-F).
- We report and analyze a set of real detection-logic and
  evaluation-tooling defects, discovered independently across both
  halves of this evaluation effort, that were found only by executing
  each evaluation against live infrastructure rather than through code
  review or synthetic-data testing, and argue this generalizes as a
  methodological requirement for evaluating systems whose correctness
  depends on multi-source event timing and cross-process state (§VII).

The remainder of this paper is organized as follows. Section II surveys
related work. Section III states the threat model. Section IV describes
CAGE's architecture. Section V details the evaluation methodology.
Section VI presents results for each research question. Section VII
discusses lessons from building the evaluation infrastructure itself.
Section VIII states limitations and threats to validity. Section IX
concludes.

---

## II. Related Work

Falco [1], originally developed by Sysdig and now a CNCF-graduated
project, monitors kernel syscalls via eBPF or a kernel-module probe and
evaluates them against a customizable rule set, enriching events with
container and Kubernetes metadata and forwarding alerts to downstream
sinks. Cilium Tetragon [2] similarly instruments process execution and
network events via eBPF `TracingPolicy` objects. Both are
single-telemetry-source, single-event rule engines: neither correlates a
syscall-visible event with a control-plane-only event, because neither
ingests the Kubernetes audit log as a first-class input. CAGE uses
Tetragon as its eBPF telemetry producer but adds the audit-log and
correlation layers Tetragon does not provide on its own.

K8NTEXT [3] (Franzil et al., *Computer Networks*, 2026) addresses a
related but different problem: Kubernetes audit logs record each API
call largely independently, so the several secondary events a single
user action triggers are scattered through the log with little explicit
linkage. K8NTEXT reconstructs *contexts* — groupings of an actor's
action with the downstream events it caused — using a combination of
inference rules and a deep-learning model, reporting over 95% grouping
accuracy on operations involving up to 100+ correlated audit entries.
This is a log-*structuring* system rather than a technique-detection
system, and it is scoped to the audit log alone; it cannot observe the
kernel-side half of a chain such as T1021→T1059 (remote exec, visible in
the audit log, followed by the shell it spawns, visible only via eBPF).

PACED [4] (Abbas et al., IC2E 2022) targets a narrower, high-severity
problem: detecting container *escape* specifically, using kernel-level
provenance capture to identify cross-namespace events and a
`privileged_flow` rule evaluated against a CVE benchmark suite of real
escape exploits. UNICORN [5] (Han et al., NDSS 2020) is a general,
non-Kubernetes-specific host-level anomaly detector that builds and
incrementally sketches whole-system provenance graphs to detect
long-running, low-and-slow APT campaigns without predefined signatures.
P4Control [8] (Bajaber et al., IEEE S&P 2024) takes yet another
adjacent approach, enforcing decentralized information-flow-control
policy at line rate using programmable (P4) network switches combined
with a lightweight host-side eBPF primitive — a prevention mechanism at
the network layer rather than a technique-level detection system. All
three are included here because they represent provenance- and
information-flow-based schools of thought architecturally adjacent to
CAGE's own pod-identity-correlated event graph; none targets Kubernetes'
specific control-plane/kernel duality the way CAGE does, and none
performs technique-level MITRE ATT&CK mapping across a broad technique
catalog.

**Table 6** (`evaluation/person_b/tables/table6_related_work.md`)
summarizes this comparison along five axes: telemetry sources, multi-hop
chain detection, Kubernetes pod-identity correlation, live attack-graph
visualization, and false-positive mitigation strategy. It is explicitly
a **qualitative** comparison against published system descriptions
(cross-checked directly against each cited paper's own text, correcting
an earlier draft's misattributed telemetry sources for K8NTEXT and
PACED), not a quantitative benchmark — no other tool was run against
CAGE's own attack set in this project's cluster. The single highest-value
quantitative addition identified for a future revision is a head-to-head
run of vanilla Tetragon (CAGE's own eBPF backend, already present in
this project's infrastructure) against the same attack set used in
E1/E2, to produce a directly comparable precision/recall/latency
baseline — this depends on the `ABLATION_MODE=tetragon_only`
infrastructure the E2 experiment already owns, so it was deliberately
not attempted in this pass to avoid duplicating that work.

---

## III. Threat Model

**In scope.** An attacker who has already obtained code execution inside
one pod — via a vulnerable application, a supply-chain compromise, or a
misconfigured/leaked credential — and attempts to escalate: spawning
shells, moving laterally to other pods, reading Kubernetes secrets,
escalating privileges inside or out of the container, abusing RBAC, or
degrading node resources. This matches the 11 techniques in Table I.

**Trust assumptions.** The Linux kernel and eBPF subsystem are trusted;
an attacker capable of loading rogue eBPF programs or otherwise blinding
Tetragon's hooks defeats the detection substrate itself, a limitation
shared by any eBPF-based defense, not one specific to CAGE. The
Kubernetes API server and its audit log are trusted; an attacker with
control-plane-level access sufficient to disable or tamper with audit
logging is operating at a privilege level well beyond "one compromised
workload pod." CAGE's own process is trusted and assumed uncompromised —
the fault-injection evaluation (§VI-H) tests CAGE's resilience to
*infrastructure* failures affecting its own components, which is a
reliability property, not a defense against an adversary who has already
compromised CAGE itself.

**Explicitly out of scope.** Kernel/eBPF-blinding rootkits (see above);
supply-chain compromises that never trigger any of the 11 watched
behaviors; single events that are individually indistinguishable from
legitimate administrative activity when viewed in isolation — which is
precisely the motivating case for chain correlation (§VI-C); multi-cluster
lateral movement, since the pod-UID cache and correlation window are
scoped to a single cluster's API server.

**Known, deliberately measured boundary.** Several detection rules use
fixed numeric thresholds: a 5-distinct-destination burst for T1610, a
25-execution burst for T1499, and a 10-read burst for T1613. An attacker
aware of these values and disciplined enough to remain under them evades
the specific rule tuned against them. Rather than leave this as an
implicit, undisclosed limitation, RQ4 and §VI-G measure exactly where
that boundary sits.

---

## IV. System Design

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
  polling — see §VI-F for why this replaced an earlier sequential design)
  as a complementary signal to the Tetragon `tcp_connect` kprobe path.

**Detection.** CAGE currently detects 11 MITRE ATT&CK techniques:

**TABLE I. Detected MITRE ATT&CK techniques and telemetry source.**

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
T1059→T1548→T1611, and T1611→T1552. Chain detections use **episode-scoped
deduplication**: a chain fires once per continuous incident and
automatically re-arms once the underlying condition clears, tracking
whether each chain's constituent legs remain continuously satisfied
rather than using a simple fire-once-forever flag — §VI-C validates this
property empirically, and it was also, concretely, a real defect found
and fixed in a different detector (the T1499 fork-bomb rule) during this
evaluation effort (§VII), which lacked this re-arm step entirely prior to
the fix.

**Scope-exclusion design.** Every behavioral rule except T1021 (§VIII)
excludes events from CAGE's own namespace-scoped infrastructure by
namespace, not by pod name — a name-based exclusion list was found during
development to be a real evasion vector (an attacker able to name or
rename a pod to match an excluded name could suppress detection of their
own activity) and was removed in favor of the namespace-only design.

---

## V. Evaluation Methodology

**Environment.** All experiments (both detection-quality and
systems-characteristics) run against the same `kind`-provisioned 3-node
cluster (1 control-plane + 2 workers) on a single host, Tetragon v1.7.0,
Kubernetes v1.30.0, kernel 6.6.87.2 (WSL2, Linux subsystem on Windows),
`ABLATION_MODE=fused` (all consumers active) unless a specific experiment
(E2, or a future quantitative Table 6 baseline) deliberately varies it.

**Metrics and their definitions.** For per-technique detection (E1) and
chain correlation (E3), a **true positive** is a malicious trial that
produced a matching alert (`wait_for_pattern`, scoped to that trial's own
log window between its start and the next trial's start, not a
time-window match against a pool of concurrent events); a **false
positive** is a matched benign trial that produced that same alert
despite no injected attack event; a **false negative** is a malicious
trial that produced no matching alert within the detection-wait timeout.
Because each trial's own scoped log window is the source of truth,
classification does not depend on any cross-trial time-window inference
— an earlier version of the E1 script used exactly such an inference
(a shared 30-second alert-to-event matching window) and was found to
silently misclassify results for fast-firing techniques (§VII); this was
corrected before the results in §VI-A were collected. For the systems
experiments: **detection latency** (E4) is measured wall-clock-to-
wall-clock from the attack command's issuance to the corresponding alert
line appearing in the server log; **resource overhead** (E5) is
`ps -o %cpu=,rss=` sampled every 5s on the CAGE server process
specifically (not the Tetragon agent or kube-apiserver — see the scope
note in §VI-E); **cycle time** (E6) is the wall-clock gap between
consecutive full polling sweeps of the `NetworkMonitor`; **fault
recovery** (E8) distinguishes *health-flag* recovery (`/api/health`
reporting non-stale) from *functional* recovery (a real post-fault
attack is correctly detected) as two separate, both-reported
measurements, because the health flag is event-triggered and cannot by
construction prove recovery before new traffic occurs (see §VI-H).

**Statistical treatment.** Binomial proportions — per-technique recall
(E1), ablation detection rate (E2), chain re-fire rate (E3),
evasion-boundary fired/not-fired rate (E4 — *sic*, see note), and
per-scenario functional-recovery rate (E8) — are reported with **Wilson
score 95% confidence intervals**, not the normal (Wald) approximation,
because Wilson intervals remain well-behaved at the sample sizes used
here (N=10 for detection-quality experiments, N=5 reps/scenario for E8)
and at the 0%/100% observed rates that occur throughout this evaluation,
where the Wald interval degenerates to zero width and misrepresents the
true uncertainty. Continuous measurements (E4 latency, E5 CPU/RSS, E6
cycle time) are reported as mean with a 95% confidence interval computed
from the t-distribution (df = N−1), alongside median, stdev, p95,
min/max for distributional shape.

**Benign-control honesty.** Not every technique admits a meaningful
benign near-miss. Creating a privileged pod, granting cluster-admin, and
issuing an RBAC-discovery burst are inherently suspicious *at the API
level* — there is no legitimate version of "create a privileged pod"
that looks different from the audit log's point of view. For T1496,
T1613, T1548-PRIV-POD, and T1548.005 we report recall only; a contrived
benign control for these would test nothing real, and we say so
explicitly rather than omit the caveat.

**Reproducibility.** Detection-quality scripts live under
`evaluation/person_a/scripts/`; systems-characteristics scripts live
under `evaluation/person_b/scripts/`. Both take explicit CLI flags for
scale (trial counts, phase durations, replication count) and write
timestamped raw CSVs that are never overwritten silently — pilot-scale
runs were archived (`_pilot_*` / `output_pilot_N2-3/` suffixes) before
each full-scale re-run began, so both scales' raw data remain available
for inspection. `evaluation/person_b/scripts/run_full_scale_all.sh`
reproduces the full-scale systems-characteristics run end to end,
including automatic environment-recovery retries (`restart_cage.sh`) if
any stage's server connection drops mid-run; the detection-quality
scripts' exact run order and commands are documented in
`evaluation/person_a/README.md`.

---

## VI. Results

### A. RQ1 — Per-Technique Detection Accuracy (E1)

N=10 attack trials and, where a meaningful control exists, N=10 matched
benign trials, live cluster, fused configuration (180 total trials: 7
techniques with both attack and benign trials, 4 attack-only).

**TABLE IV. Per-technique detection accuracy.**

| Technique | TP | FP | FN | Precision | Recall (95% Wilson CI) | F1 | Source |
|---|---|---|---|---|---|---|---|
| T1059 | 10 | 10 | 0 | 50.0% | 100% [72.2%, 100%] | 66.7% | Tetragon |
| T1021 | 10 | 10 | 0 | 50.0% | 100% [72.2%, 100%] | 66.7% | Audit |
| T1552 | 10 | 0 | 0 | 100% | 100% [72.2%, 100%] | 100% | Audit |
| T1610 | 10 | 0 | 0 | 100% | 100% [72.2%, 100%] | 100% | Tetragon |
| T1611 | 10 | 10 | 0 | 50.0% | 100% [72.2%, 100%] | 66.7% | Tetragon |
| T1548 | 10 | 10 | 0 | 50.0% | 100% [72.2%, 100%] | 66.7% | Tetragon |
| T1499 | 10 | 0 | 0 | 100% | 100% [72.2%, 100%] | 100% | Tetragon |
| T1496† | 10 | 0 | 0 | — | 100% [72.2%, 100%] | — | Tetragon |
| T1613† | 10 | 0 | 0 | — | 100% [72.2%, 100%] | — | Audit |
| T1548-PRIV-POD† | 10 | 0 | 0 | — | 100% [72.2%, 100%] | — | Audit |
| T1548.005† | 10 | 0 | 0 | — | 100% [72.2%, 100%] | — | Audit |

† No meaningful benign control exists (§V); precision not computed for
these four rows.

Fig. 5 visualizes Table IV as a per-technique precision/recall/F1
heatmap, with each technique's recall confidence interval annotated
directly on the cell and an asterisk marking the four techniques with no
benign control. Recall is 100% across all 11 techniques with a 95%
confidence floor of 72.2% at this sample size — every attack trial was
detected, in every trial, with no exceptions. Precision divides the
technique set exactly
along the design boundary stated in §IV: the four techniques with no
scope exclusion (T1059, T1021, T1548, T1611) show precisely 50%
precision because they correctly fire on the matched benign action as
well as the attack action; the three techniques with genuine behavioral
discrimination in this table (T1552, T1610, T1499) show 100% precision.

Detection latency for these trials falls into two clusters, consistent
with the dedicated latency evaluation in §VI-D: audit-log-sourced
detections and the Tetragon capability-check (T1611) resolve in 0-4
seconds; several Tetragon-sourced detections (T1059, T1548, T1499,
T1496, T1610) resolve in 26-30 seconds, matching the ~28s plateau
characterized independently and at larger scale in §VI-D.

### B. RQ2 — Cross-Layer Necessity: Telemetry-Source Ablation (E2)

N=10 trials per technique per condition, 3 conditions
(`tetragon_only`, `audit_only`, `fused`), 330 total trials.

**TABLE V. Ablation study: detection rate by telemetry configuration.**

| Technique | Tetragon only | Audit log only | Fused |
|---|---|---|---|
| T1059 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1021 | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| T1552 | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| T1610 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1611 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1548 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1496 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1499 | 10/10 (100%) | 0/10 (0%) | 10/10 (100%) |
| T1613 | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| T1548-PRIV-POD | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |
| T1548.005 | 0/10 (0%) | 10/10 (100%) | 10/10 (100%) |

Fig. 3 renders Table V as a heatmap and Fig. 4 as a per-tactic radar
chart, both making the complementary-coverage pattern visually immediate.
This is the paper's central empirical argument for cross-layer fusion.
The split is perfectly complementary with zero exceptions across 220
single-source trials: every technique is detected with 0% probability
under exactly one single-source condition and 100% under the other, and
the fused condition recovers 100% detection across all 11 techniques.
No technique requires *both* sources simultaneously, but no *single*
source covers more than 6 of the 11 — meaning an operator running either
tool alone, regardless of tuning effort on the deployed side, carries a
structural blind spot over roughly half the technique catalog that no
threshold adjustment can close. Only adding the missing telemetry source
closes it. This result directly substantiates the motivating claim in
§I with controlled, live-cluster measurement rather than architectural
argument alone.

### C. RQ3 — Chain-Correlation Reliability (E3)

N=10 trials per chain, all 5 documented chains, each trial pair
separated by >120s (exceeding the correlation window) to force
genuinely independent episodes, and each chain-type block separated from
the next by the same margin, since several chains share overlapping
trigger actions (§VII discusses a live-discovered timing pitfall here).
50 total trials, live cluster, current (fixed) episode-scoped dedup
logic.

**TABLE VI-C. Chain re-detection across independent episodes.**

| Chain | Fired / N |
|---|---|
| T1059→T1552 | 10/10 |
| T1021→T1059→T1552 | 10/10 |
| T1059→T1610→T1552 | 10/10 |
| T1059→T1548→T1611 | 10/10 |
| T1611→T1552 | 10/10 |

Fig. 8 plots cumulative detections per trial for a representative chain
against the ideal one-per-trial diagonal, illustrating this reliability
visually alongside the full per-chain breakdown in Table VI-C. Every
documented chain re-fires reliably across 10 independent episodes each,
with zero missed detections (50/50). This directly validates the
episode-scoped re-arm design described in §IV: had the earlier,
fire-once-forever dedup behavior (§VII, defect 1) still been present, at
most the *first* trial of each chain would have fired and every
subsequent trial against the same long-lived pod would have been a false
negative — the empirical signature of that defect class is precisely a
1/10 result, not the 10/10 observed here.

### D. RQ5 — Detection Latency (E4)

**Scale:** full plan spec, N=20 trials/technique for the distribution
measurement. See `evaluation/person_b/tables/table4_latency.md` and
`evaluation/person_b/RESULTS.md` for full detail.

Fig. 6 plots the latency distribution for both techniques as empirical
CDFs, making the bimodal source split visually explicit. Detection
latency is cleanly bimodal by source, and the split tightens further at
full scale. Audit-log-sourced detections (T1552) are fast and tight:
mean 0.19s, 95% CI [0.18, 0.20], across N=20 trials.
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
table and reasoning, and §VIII for the general lesson this adds to the
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

### E. RQ6 — Resource Overhead (E5)

**Scale:** full plan spec, idle_pre=300s / active=600s / idle_post=300s,
241 total samples. This is the corrected re-run after a stale-process PID
bug caused the first full-scale attempt to measure the wrong process
entirely (0.0% CPU / 1.7MB RSS — see RESULTS.md's "Bugs found" section);
fixed and re-run clean. See `evaluation/person_b/tables/table5_overhead.md`.

Fig. 9 plots CPU and RSS over the full idle/active/idle timeline,
showing both flat lines directly. CPU usage on the CAGE server process
is flat at 3.1–3.2% across idle and active phases alike, with no visible
spike under a repeating T1059+T1552 attack load every 3 seconds. RSS is
flat at 134.8–134.9MB, growing by
only ~0.1MB across the full 20-minute run — this longer, full-scale
window resolves the pilot run's explicitly-flagged ambiguity ("too short
to distinguish a small bounded constant term from a slow leak") in favor
of **bounded**: a 5x longer active phase generating substantially more
events shows growth essentially stopping, consistent with the periodic
stale-entry sweep reclaiming memory as designed rather than a leak.

Overhead here is scoped to the CAGE server process only, not Tetragon's
own per-node agent cost, which this `kind`-based cluster's tooling cannot
measure without a metrics-server this evaluation did not install (§VIII).

### F. RQ7 — NetworkMonitor Polling Scalability (E6)

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

### G. RQ4 — Evasion Boundary Characterization (E9)

N=10 trials per boundary per technique, default thresholds, live
cluster. This experiment answers RQ4 directly; it is a fixed-threshold
boundary characterization, distinct from a full multi-value threshold
*sweep* (varying the threshold itself across several values), which was
explicitly descoped from this evaluation cycle for time (§VIII).

For T1610 and T1613, "just under" is exactly one unit below the
documented default threshold; for T1499, "just under" uses a
deliberately wider margin (15 versus the threshold of 25) rather than
exactly 24, for a reason reported honestly rather than concealed: live
measurement of the exact per-invocation process-count overhead of the
attack-firing helper proved unreliable across repeated, carefully-spaced
trials, and a defensible-but-imprecise boundary claim was judged
preferable to an exact-sounding one the evidence did not actually
support (§VII).

**TABLE VII. Evasion boundary results, default thresholds.**

| Technique | Just under threshold | At threshold |
|---|---|---|
| T1610 (threshold 5) | 0/10 fired | 10/10 fired |
| T1499 (threshold 25) | 0/10 fired | 10/10 fired |
| T1613 (threshold 10) | 0/10 fired | 10/10 fired |

Fig. 10 plots this boundary as a per-technique dot plot, both boundary
conditions shown side by side. All three threshold-based detectors show
the same clean pattern: an attacker who knows the default threshold and
stays under it evades detection with certainty (0/10 across 30 total
sub-threshold trials); an attacker who reaches the threshold is caught
with equal certainty (10/10
across 30 total at-threshold trials). We report this as a measured,
disclosed property of a threshold-based detector (§III) rather than as a
weakness discovered post hoc — the threat model explicitly scopes this
boundary as known and deliberately characterized, and this experiment is
that characterization.

### H. RQ8 — Fault Injection and Recovery (E8)

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
Fig. 2 shows a representative recovery timeline across all three
scenarios.

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

Spurious-alert counts (4 total alerts across the 5 tetragon-kill
windows, 12 across the 5 audit-truncate windows, 0 across the 5
control-plane-outage windows) remain proportionally consistent with the
attacker pod's own ~30-second background T1059 loop
landing inside the longer fault windows, rather than evidence of
fault-induced false detections — audit-truncate and control-plane-outage
both have multi-minute functional-recovery windows, giving the
background loop more chances to fire during them. This pilot-noted
methodology gap (the background loop is not isolated or controlled for)
still applies at full scale and is carried into §VIII unchanged; an
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

## VII. Lessons from Live-System Evaluation

Several real defects were found only by executing each half of this
evaluation against live infrastructure, not by code review or testing
against synthetic data. From the detection-quality evaluation:

1. A fork-bomb detector (T1499) whose deduplication state was never
   cleared once set, meaning the rule could fire at most **once** for a
   given pod's entire lifetime — a genuine detection gap for any
   workload subject to more than one such burst, not merely a test
   artifact. Fixed by adding the same episode-scoped re-arm logic already
   used by the chain correlator (§IV).
2. A metrics-collection scheme whose 30-second alert-to-event matching
   window silently reclassified benign-trial false positives as true
   positives for techniques with near-zero detection latency, because a
   benign trial's alert fell within the matching window of a nearby
   *malicious* trial's own event. This would have reported spuriously
   high precision for exactly the techniques (T1021, T1611) whose design
   guarantees they fire unconditionally.
3. A chain-alert search pattern containing a literal Unicode-arrow
   (`→`) versus ASCII-hyphen (`->`) mismatch against the system's actual
   log output — indistinguishable, without direct log inspection, from a
   genuine detection failure.
4. Several evaluation-script crashes caused by uncaught transient
   subprocess timeouts, which — combined with an evaluation script that
   originally wrote its results only once, at completion — meant a single
   momentary `kubectl` hiccup an hour into an N=10 run could discard every
   trial collected up to that point. Fixed by catching the timeout at the
   call site and by writing every result to disk immediately after each
   trial rather than only at the end.

From the systems-characteristics evaluation, independently:

5. A stale restart-wrapper process silently mistaken for the CAGE server
   by substring-based `pgrep` matching, corrupting two full-scale
   measurements (E5 resource overhead, reporting 0.0% CPU / 1.7MB RSS for
   a process that was not actually the server; E8 functional-recovery,
   pointing the recovery check at the wrong log file for 13 of 15
   trials) before detection. Both were caught by sanity-checking against
   physically plausible ranges, fixed by disambiguating the true server
   process, and re-run clean.

Two independent evaluation efforts on the same codebase, testing
different subsystems (detection logic versus systems performance),
each surfaced multiple defects invisible to code review; neither found
the other's defects by inspection, and neither anticipated the other's
specific failure mode in advance. We surface this not as an incidental
footnote but as a methodological claim: for systems whose correctness
depends on multi-source event timing and cross-process state — dedup
flags, correlation windows, alert buffers, or process-identity
bookkeeping — static analysis and unit-level testing are necessary but
not sufficient, and an evaluation pipeline that never executes against
the live target system risks reporting fabricated confidence.

---

## VIII. Limitations and Threats to Validity

- **Environment scope.** A single-control-plane, two-worker `kind`
  cluster inside a WSL2 VM is not a production-scale, multi-node,
  bare-metal Kubernetes topology; detection latency and resource-overhead
  results may not generalize unchanged to substantially larger or
  bare-metal deployments, and audit-log access requires apiserver-manifest
  patching not always available on managed control planes.
- **Kernel/BTF dependency.** T1610 (network lateral movement) requires a
  BTF-enabled kernel (5.10+); confirmed functional on kernel 6.6,
  cross-environment portability (e.g., managed offerings with restricted
  kernel access) not independently verified.
- **Virtualization-environment generalizability.** All latency/overhead
  numbers were measured inside a VM; relative findings (the source-latency
  gap, bounded overhead) likely generalize, but absolute numbers — the
  ~28s Tetragon plateau specifically — may not transfer unchanged to bare
  metal, untested here.
- **T1021 scope.** T1021 carries no scope exclusion at all, flagging
  every `kubectl exec` including routine administrative access — an
  accepted, documented precision cost (§IV, VI-A), not an oversight, but
  one that would need revisiting for a production deployment with a high
  baseline rate of legitimate `kubectl exec` traffic. The 120-second
  correlation window similarly bounds how slow a multi-hop attack can be
  and still be linked into one chain alert.
- **Synthetic, non-adaptive attack scripts.** Every attack in this
  evaluation is a fixed, disclosed, non-evasive command sequence.
  Detection numbers characterize behavior against this specific,
  published attack set — not robustness against an adversary
  deliberately trying to evade these exact rules beyond the specific,
  disclosed threshold boundary measured in §VI-G.
- **T1499 evasion-boundary precision.** §VI-G's T1499 result uses a
  comfortably-under-threshold value (15 versus the threshold of 25)
  rather than an exact threshold-minus-one boundary, for the reason
  reported in §VII: the exact process-count overhead of the
  attack-firing mechanism itself proved difficult to pin down reliably
  in live testing. T1610 and T1613's boundaries are exact.
- **Limited adversarial evasion testing.** The one real evasion vector
  found and fixed during development (name-based scope exclusion) was
  found incidentally, not via systematic red-teaming; other evasion
  strategies (timing fragmentation across the correlation window, binary
  renaming) remain untested.
- **Sample size.** N=10 per condition (detection-quality experiments)
  narrows the 95% CI to a floor of 72.2% at 10/10 — a substantial
  improvement over pilot N=2-3 data, but a larger N would further
  tighten intervals, particularly relevant near any future severity- or
  threshold-boundary claims. Fault-injection trials (E8) use N=5
  reps/scenario for practical session-time reasons rather than a formal
  power analysis; confidence intervals are reported throughout
  specifically so this uncertainty is visible rather than hidden behind
  point estimates.
- **Deferred experiments.** An old-code-versus-new-code comparison for
  the chain-correlation fix (§IV), and a threshold-sweep experiment
  varying detection thresholds across multiple values rather than only
  default-versus-boundary, were both explicitly descoped from this
  evaluation cycle for time. Neither affects the validity of the results
  that are included; both would add depth to, respectively, §VI-C and
  §VI-G.
- **No quantitative baseline.** Table 6 is qualitative; a head-to-head
  vanilla-Tetragon comparison (the cheapest quantitative addition,
  dependent on the E2 ablation infrastructure) remains future work.
- **Attack-chain timeline figure not yet built.** A planned illustrative
  figure showing one representative multi-hop chain's timeline
  (T1021→T1059→T1552, annotated by telemetry source) requires
  hand-curating real timestamps from a server log rather than being
  auto-generated from the trial CSVs like the other figures, and was not
  completed in this evaluation cycle. The plotting script and CSV
  template exist (`evaluation/person_a/plots/plot_fig1_chain_timeline.py`);
  populating it with real data from an E1 or E3 run is a short remaining
  task before final submission.
- **Tetragon delivery-latency mechanism not conclusively root-caused.**
  The ~28s plateau (§VI-D) is characterized precisely and highly
  reproducibly (N=20, σ=0.17s) but its underlying cause within Tetragon's
  own event-delivery path was not identified within this project's
  scope; an attempted fix was reverted after live testing showed it
  traded latency for event loss.
- **Connection-age dependence is an open question, not resolved.** Two
  connage sweeps at different scales gave contradictory results, with
  evidence pointing to a post-restart event-backlog confound in the
  full-scale run rather than a genuine change in system behavior;
  neither the original age-dependence hypothesis nor its pilot-scale
  revision is re-confirmed (§VI-D).
- **This evaluation's own measurement infrastructure had reproducible
  failure modes**, caught and fixed during data collection on both
  sides — see §VII for the full account. Reported transparently as a
  property of the evaluation environment worth documenting for anyone
  extending this suite, not retroactively minimized.

---

## IX. Conclusion

This paper presented CAGE, a cross-layer Kubernetes runtime security
system that fuses eBPF telemetry with the Kubernetes audit log via a
pod-identity-keyed correlator, and evaluated it entirely on live
infrastructure along two axes and eight explicit research questions.

On detection quality: per-technique recall reached 100% across all 11
detected MITRE ATT&CK techniques (RQ1). A 330-trial ablation study
produced this paper's central empirical result: a perfectly
complementary 0%/100% detection split across 220 single-source trials,
recovered to 100% only once both telemetry sources were fused, with no
single source covering more than six of the eleven techniques (RQ2) —
direct, controlled evidence that cross-layer fusion is not an
incremental improvement over single-source detection for this technique
set, but a structural requirement for full coverage. All five documented
attack chains re-armed and re-fired correctly across ten independent
episodes each, validating the system's episode-scoped correlation design
against the specific failure mode — permanent, fire-once deduplication —
that an earlier version of the codebase actually exhibited (RQ3). CAGE's
three threshold-based detectors each drew a clean, disclosed line
between certain evasion and certain detection at their documented
default thresholds (RQ4).

On systems characteristics: CAGE achieves this detection coverage at a
flat, load-independent resource cost (~3.2% CPU, ~135MB RSS) (RQ6), with
a monitoring subsystem whose polling cycle time holds flat across an
order-of-magnitude range of monitored-pod counts after a concurrency fix
that also closed a real detection-evasion path in the process (RQ7), and
functionally self-heals from all three tested classes of injected
infrastructure fault without manual intervention (RQ8) — at the
disclosed cost of a highly consistent ~28-second detection-latency
plateau on eBPF-sourced technique classes specifically, whose precise
cause and dependence on connection age remain open, honestly-reported
questions rather than settled findings (RQ5).

Beyond these results, this evaluation effort — conducted as two
independent halves testing different subsystems — surfaced multiple real
detection-logic and evaluation-tooling defects that static analysis
alone did not catch on either side, a finding that we believe
generalizes beyond this system to any runtime security tool whose
correctness depends on cross-process state and multi-source event
timing: such systems should be evaluated by running them, not only by
reading them.

---

## References

*(Citations verified via direct retrieval of the cited papers' own text
this session, not carried forward from earlier, unverified project
documentation; exact page ranges/DOIs should be cross-checked against
final published versions before submission.)*

[1] The Falco Project, Cloud Native Computing Foundation. [Online].
Available: https://falco.org/

[2] Cilium Tetragon, Cilium project / Isovalent. [Online]. Available:
https://tetragon.io/

[3] M. Franzil, V. Armani, L. A. Dias Knob, and D. Siracusa, "Sharpening
Kubernetes audit logs with context awareness," *Computer Networks*, vol.
276, Feb. 2026. Also available: arXiv:2506.16328.

[4] M. Abbas, S. Khan, A. Monum, F. Zaffar, R. Tahir, D. Eyers, H.
Irshad, A. Gehani, V. Yegneswaran, and T. Pasquier, "PACED:
Provenance-based automated container escape detection," in *Proc. 2022
IEEE Int. Conf. Cloud Eng. (IC2E)*, San Francisco, CA, USA, Apr. 2022,
pp. 261–272. *(Page range as reported by secondary sources; verify
against the IEEE Xplore record before submission.)*

[5] X. Han, T. Pasquier, A. Bates, J. Mickens, and M. Seltzer, "UNICORN:
Runtime provenance-based detector for advanced persistent threats," in
*Proc. Network and Distributed System Security Symp. (NDSS)*, San Diego,
CA, USA, Feb. 2020. Also available: arXiv:2001.01525.

[6] Red Hat, "The state of Kubernetes security report: 2024 edition,"
Red Hat, Inc., 2024. Survey of 600 DevOps, engineering, and security
professionals; 89% of respondents reported at least one container- or
Kubernetes-related security incident in the preceding 12 months, and 45%
reported a runtime-specific incident. [Online]. Available:
https://www.redhat.com/en/engage/state-kubernetes-security-report-2024

[7] Wiz Research, "Kubernetes Security Report 2025," Wiz, Inc., 2025.
Reports that newly created clusters on Microsoft AKS and Amazon EKS
receive a first attack attempt within 18 and 28 minutes of deployment,
respectively, based on analysis of over 200,000 cloud accounts. [Online].
Available: https://www.wiz.io/reports/kubernetes-security-report-2025

[8] O. Bajaber, B. Ji, and P. Gao, "P4Control: Line-rate cross-host
attack prevention via in-network information flow control enabled by
programmable switches and eBPF," in *Proc. 2024 IEEE Symp. Security and
Privacy (S&P)*, San Francisco, CA, USA, May 2024. Also available:
arXiv:2405.14970.

*(Additional references needed before submission: the MITRE ATT&CK
framework itself, the Wilson score interval's original source [E. B.
Wilson, "Probable inference, the law of succession, and statistical
inference," J. Amer. Statist. Assoc., vol. 22, no. 158, pp. 209–212,
1927] if cited by name in the methodology, and any further general
Kubernetes/container-security survey citations a reviewer might expect
in §I's opening framing. At least 10-15 more citations beyond the
direct related-work comparison are standard for an IEEE Access paper of
this scope — a full literature-review pass is recommended before
submission.)*

---

## Appendix: Reproducibility Artifacts

- Person A scripts, data, figures, tables: `evaluation/person_a/`
  (see `evaluation/person_a/README.md` for exact run order and commands)
- Person B scripts, data, figures, tables: `evaluation/person_b/`
- Master full-scale re-run driver (Person B):
  `evaluation/person_b/scripts/run_full_scale_all.sh`
- Environment rebuild: `restart_cage.sh` (repo root)
- Pilot-scale raw data (archived, not deleted, for comparison):
  `evaluation/person_b/data/*_pilot_*.csv`,
  `evaluation/person_a/output_pilot_N2-3/`
- Evaluation-plan review and gap analysis:
  `EVALUATION_REVIEW.md` (Person B's review, repo root) and
  `EVALUATION_REVIEW_PERSON_A.md` (Person A's independent review, repo
  root) — both review the same `EVALUATION_PLAN.md` from each
  contributor's own domain and should both be consulted.
- Full session narrative and complete bug list for Person A's evaluation:
  `evaluation/person_a/SESSION_REPORT.md`
