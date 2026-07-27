# CAGE: A Cross-Layer Attack Graph Engine for Kubernetes Runtime Security

**SUPERSEDED.** This standalone draft has been merged into
`evaluation/MANUSCRIPT_DRAFT.md`, which is now the single canonical
manuscript combining this file's detection-quality content (E1/E2/E3/E9)
with Person B's systems-characteristics content (E4/E5/E6/E8) into one
paper with a shared Abstract, Introduction, Related Work, Threat Model,
System Design, Methodology, Results (organized by 8 research questions
across both evaluation axes), Lessons Learned, Limitations, and
Conclusion. Edit `evaluation/MANUSCRIPT_DRAFT.md` going forward, not this
file — kept here only as a historical/reference copy of Person A's
original independent draft and its citation-verification work.

*Original header, retained for reference: Draft, structured to IEEE
Access conventions. Person A's scope (E1/E2/E3/E9) is complete at N=10
with every number below drawn from real live-cluster data. Citations for
Related Work were verified via web search this session (not fabricated);
exact page/DOI details should still be cross-checked against
camera-ready versions before submission — see inline notes.*

---

## Abstract

Kubernetes security has not kept pace with Kubernetes adoption: 89% of
organizations report at least one container- or Kubernetes-related
security incident in the past year, and newly deployed clusters can draw
their first attack probe within minutes of coming online. Runtime
security tools have responded by instrumenting a single telemetry
source — kernel-level activity via eBPF, or the control-plane audit
log — and alerting on individual events that match a known-bad pattern.
This design has a structural blind spot: several attacker-relevant
actions are visible on only one side of the kernel/control-plane
boundary, so a tool watching only that side cannot distinguish a genuine
multi-step intrusion from two unrelated, benign-looking events. We
present CAGE (Cross-layer Attack Graph Engine), a system that fuses eBPF
telemetry with the Kubernetes audit log via a live pod-identity cache
keyed on the pod UID — immutable for a pod's lifetime — to detect 11
MITRE ATT&CK techniques and correlate them into five multi-hop attack
chains with episode-scoped deduplication. Evaluated entirely on live
Kubernetes infrastructure, CAGE achieves 100% per-technique recall
across all 11 techniques (220 trials). A three-condition, 330-trial
ablation study reveals a perfectly complementary telemetry split — every
technique is detected with 0% probability under one single-source
configuration and 100% under the fused one, and no single source covers
more than six of the eleven — evidencing that cross-layer fusion is
structurally required, not merely beneficial. All five attack chains
re-fire reliably across ten independent episodes each (50/50 trials),
and we further characterize the evasion boundary of CAGE's
threshold-based detectors. We also report real detection-logic defects
that surfaced only once the evaluation was executed against live
infrastructure, with implications for how systems of this kind should be
evaluated more broadly.

**Index Terms**—Kubernetes security, eBPF, runtime intrusion detection,
audit log analysis, attack chain correlation, MITRE ATT&CK, cross-layer
telemetry fusion, cloud-native security.

---

## I. Introduction

Kubernetes has become the de facto standard for orchestrating containerized
workloads in cloud and enterprise environments, valued for the scalability
and operational automation it brings to deployments that would otherwise
require substantial manual effort to manage across many nodes [6]. That
ubiquity has made Kubernetes clusters an attractive and heavily probed
target: a 2024 industry survey of 600 DevOps, engineering, and security
professionals found that 89% of organizations had experienced at least
one container- or Kubernetes-related security incident in the preceding
year, and 45% specifically reported a runtime incident [6]. Independent
honeypot research on managed Kubernetes offerings corroborates how
quickly this exposure is exploited in practice: newly created clusters
received their first attack attempt within 18 minutes on Microsoft AKS
and within 28 minutes on Amazon EKS [7].

The security-tooling response to this exposure has largely followed the
pattern established by host-based intrusion detection two decades
earlier: instrument one telemetry source in depth, and raise an alert
when a single observed event matches a known-bad pattern. Falco [1] and
Cilium Tetragon [2], two of the most widely adopted open-source runtime
security tools for Kubernetes, both instrument the kernel — via eBPF or
a kernel-module probe — and evaluate syscall- and process-level events
against a rule set. K8NTEXT [3] takes the complementary approach at the control-plane layer,
reconstructing the causal structure the Kubernetes audit log otherwise
scatters across thousands of loosely linked entries. Each of these tools
is, within its own telemetry source, mature and effective. None of them,
by design, looks at the other source at all.

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
workload, the sequence is a materially stronger signal than either event
is alone — but a tool that instruments only one side of that boundary
never has the opportunity to make that observation, regardless of how
well it is tuned.

Existing work has not closed this gap. Falco and Tetragon operate
exclusively on eBPF telemetry and evaluate each event independently, with
no mechanism to correlate a kernel-side event with a control-plane one.
K8NTEXT operates exclusively on the audit log, and while it reconstructs
which control-plane events a given action caused, it has no visibility
into what happened inside the pod as a result — it cannot see the shell
that a correlated `kubectl exec` spawned. PACED [4] and UNICORN [5]
represent a third, provenance-graph-based school of thought that CAGE is
architecturally adjacent to, but neither closes this specific gap either:
PACED targets a single technique family (container escape) via kernel
provenance capture, and UNICORN is a general-purpose, non-Kubernetes-
specific anomaly detector built for slow-acting APT campaigns rather than
technique-level classification against a broad catalog. None of these
systems fuses eBPF telemetry with the Kubernetes audit log through a
stable, workload-level identity key to detect and correlate a broad
MITRE ATT&CK technique catalog — which is the specific gap this paper
addresses.

To this end, this paper investigates the following research questions:

- **RQ1.** What is CAGE's per-technique detection accuracy, and how does
  that accuracy differ between techniques with and without a deliberate
  scope exclusion? (Section VI-A)
- **RQ2.** Does any single telemetry source achieve full detection
  coverage across CAGE's technique catalog, or is cross-layer fusion
  structurally required to do so? (Section VI-B)
- **RQ3.** Does CAGE's chain correlator reliably re-detect independent
  instances of the same multi-step attack against the same workload,
  validating its episode-scoped deduplication design? (Section VI-C)
- **RQ4.** For CAGE's threshold-based detectors, where exactly does the
  boundary between detection and evasion sit relative to the documented
  default thresholds? (Section VI-D)

To answer these questions, we designed and evaluated CAGE, a Kubernetes
runtime security system that fuses Tetragon's eBPF telemetry with the
Kubernetes audit log, correlating events from both sources by pod UID —
a value assigned at pod creation and immutable for the pod's lifetime,
unlike its IP address or name, either of which can be reused or reassigned
within a cluster's lifetime. Every result reported in this paper was
obtained by executing CAGE and the corresponding attack simulations
against a live three-node Kubernetes cluster; none is derived from
simulation, mocked telemetry, or synthetic data.

**Contributions.** The contributions of this paper are summarized as
follows:

- We present CAGE, a cross-layer runtime security architecture that
  fuses eBPF process and network telemetry with Kubernetes audit-log
  events through a live, watch-API-backed pod-identity cache, detecting
  11 MITRE ATT&CK techniques and correlating them into five documented
  multi-hop attack chains with episode-scoped deduplication (Section IV).
- We evaluate CAGE on live Kubernetes infrastructure against four
  explicit research questions, reporting per-technique detection
  accuracy with Wilson-confidence-interval-backed statistics, a
  telemetry-source ablation study, chain-correlation reliability across
  independent episodes, and an evasion-boundary characterization of the
  system's threshold-based detectors (Sections V-VI).
- We report and analyze a set of real detection-logic and
  evaluation-tooling defects that were found only by executing the
  evaluation against live infrastructure rather than through code review
  or synthetic-data testing, and argue this generalizes as a
  methodological requirement for evaluating systems whose correctness
  depends on multi-source event timing and cross-process state
  (Section VII).

The remainder of this paper is organized as follows. Section II surveys
related work. Section III states the threat model. Section IV describes
CAGE's architecture. Section V details the evaluation methodology.
Section VI presents results for each research question. Section VII
discusses lessons from building the evaluation infrastructure itself.
Section VIII states limitations and threats to validity. Section IX
concludes.

---

## II. Related Work

**Syscall/eBPF-based runtime security.** Falco [1], originally developed
by Sysdig and now a CNCF-graduated project, monitors kernel syscalls via
eBPF or a kernel-module probe and evaluates them against a customizable
rule set, enriching events with container and Kubernetes metadata (pod
name, labels) and forwarding alerts to over 50 downstream sinks. Cilium
Tetragon [2] similarly instruments process execution and network events
via eBPF `TracingPolicy` objects. Both are single-telemetry-source,
single-event rule engines: neither correlates a syscall-visible event
with a control-plane-only event to form a multi-step detection, because
neither ingests the Kubernetes audit log as a first-class input. CAGE
uses Tetragon as its eBPF telemetry producer but adds the audit-log and
correlation layers Tetragon does not provide on its own.

**Audit-log-based analysis.** K8NTEXT [3] (Franzil et al., *Computer
Networks*, 2026) addresses a different but related problem: Kubernetes
audit logs record each API call largely independently, so the several
secondary events a single user action triggers are scattered through the
log with little explicit linkage. K8NTEXT reconstructs *contexts* —
groupings of an actor's action with the downstream events it caused —
using a combination of inference rules and a deep-learning model, and
reports over 95% grouping accuracy on operations involving up to 100+
correlated audit entries. This is a log-*structuring* system rather than
a technique-detection system, and it is scoped to the audit log alone; it
does not ingest eBPF telemetry, and so — by the same single-source
argument this paper makes in Section I — it cannot observe the kernel-side
half of a chain such as T1021→T1059 (remote exec, visible in the audit
log, followed by the shell it spawns, visible only via eBPF).

**Provenance-graph-based detection.** PACED [4] (Abbas et al., IC2E
2022) targets a narrower, high-severity problem: detecting container
*escape* specifically, using kernel-level provenance capture to identify
cross-namespace events and a `privileged_flow` rule evaluated against a
CVE benchmark suite of real escape exploits. UNICORN [5] (Han et al.,
NDSS 2020) is a general (not Kubernetes-specific) host-level anomaly
detector that builds and incrementally sketches whole-system provenance
graphs to detect long-running, low-and-slow APT campaigns without
predefined signatures. Both systems are included here because they
represent the provenance-graph school of thought that CAGE's own
pod-identity-correlated event graph is architecturally adjacent to;
neither targets Kubernetes' specific control-plane/kernel duality the way
CAGE does, and neither performs technique-level MITRE ATT&CK mapping
across a broad technique catalog — PACED is escape-specific, and UNICORN
is anomaly-based rather than rule-based and pre-dates Kubernetes-specific
tooling entirely.

**Summary comparison (Table VI).**

| System | Telemetry source(s) | Multi-hop chain detection | K8s pod-identity correlation | Live dashboard | Scope |
|---|---|---|---|---|---|
| Falco [1] | eBPF/syscalls | No (single-event rules) | Partial (container/pod metadata, not a stable UID join key) | No (alert sink only) | General runtime rule engine |
| Tetragon (standalone) [2] | eBPF (process, network) | No (single-event policies) | Partial (K8s API enrichment) | No | General eBPF policy engine |
| K8NTEXT [3] | K8s audit log only | Context-grouping (not MITRE-technique-level chain detection) | Not specified in the published evaluation | No | Audit-log structuring/noise reduction |
| PACED [4] | Kernel provenance | No (single technique family: container escape) | No | No | Container escape detection only |
| UNICORN [5] | Host-level provenance graph | Anomaly-based long-range correlation (not Kubernetes-specific) | N/A (not Kubernetes-scoped) | No | General-purpose APT detection |
| **CAGE (this work)** | eBPF (Tetragon) + K8s audit log | **Yes — 5 documented MITRE-technique chains, 120s correlation window, episode-scoped dedup** | **Yes — pod UID as join key** | **Yes — SSE-streamed dashboard** | 11 MITRE ATT&CK techniques + chain correlation |

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
workload pod." CAGE's own process is trusted and assumed uncompromised.

**Explicitly out of scope.** Kernel/eBPF-blinding rootkits (see above);
supply-chain compromises that never trigger any of the 11 watched
behaviors; single events that are individually indistinguishable from
legitimate administrative activity when viewed in isolation — which is
precisely the motivating case for chain correlation (Section VI-C);
multi-cluster lateral movement, since the pod-UID cache and correlation
window are scoped to a single cluster's API server.

**Known, deliberately measured boundary.** Several detection rules use
fixed numeric thresholds: a 5-distinct-destination burst for T1610, a
25-execution burst for T1499, and a 10-read burst for T1613. An attacker
aware of these values and disciplined enough to remain under them evades
the specific rule tuned against them. Rather than leave this as an
implicit, undisclosed limitation, RQ4 (Section V) and Section VI-D
measure exactly where that boundary sits.

---

## IV. System Architecture

### A. Overview

```
Tetragon eBPF stream ──┐
                        ├─→ shared queue → CausalGraph → alerts → SSE → dashboard
K8s Audit Log stream ──┤
Network Monitor ───────┘
        ↑
   Pod UID Cache (K8s watch API — the correlation key across all sources)
```

Three independent telemetry producers write to a shared event queue. A
pod-identity cache, populated and kept current via the Kubernetes watch
API, resolves each event's originating container to a stable pod UID
regardless of which telemetry source produced the event. The
`CausalGraph` component consumes the fused, identity-tagged queue and
performs two roles: (i) per-technique rule evaluation against the 11
techniques in Table I, and (ii) multi-hop chain correlation against the 5
chains in Table III, using a 120-second sliding window keyed by pod UID.

### B. Chain Correlation and Episode-Scoped Deduplication

A chain fires once per continuous incident. Rather than a simple
fire-once-forever flag, the correlator tracks whether each chain's
constituent legs remain continuously satisfied and discards the
"already fired" state once they are not — allowing a *new* episode
against the same pod to fire independently, rather than the first
detection permanently silencing all future ones for that workload's
lifetime. Section VI-C validates this property empirically; it was also,
concretely, a real defect found and fixed in the fork-bomb detector
during this evaluation effort (Section VII), which lacked this re-arm
step entirely prior to the fix.

### C. Detected Techniques

**TABLE I. Detected MITRE ATT&CK techniques and telemetry source.**

| Technique | Description | Severity | Source |
|---|---|---|---|
| T1059 | Shell spawned inside a pod | MEDIUM | Tetragon eBPF |
| T1021 | Remote exec (`kubectl exec`) | MEDIUM | K8s audit log |
| T1610 | Pod-to-pod network lateral movement (5-destination burst / 10s) | MEDIUM | Tetragon kprobe |
| T1552 | Secret access via K8s API | HIGH | K8s audit log |
| T1611 | Container escape (dangerous capability / escape binary) | HIGH | Tetragon eBPF |
| T1548 | Privilege escalation inside a container | HIGH | Tetragon eBPF |
| T1548-PRIV-POD | Privileged pod created | HIGH | K8s audit log |
| T1548.005 | Cluster-admin / wildcard RBAC grant | CRITICAL | K8s audit log |
| T1496 | Cryptomining process signature | HIGH | Tetragon eBPF |
| T1499 | Fork-bomb-like exec burst (25-execution burst / 10s) | HIGH | Tetragon eBPF |
| T1613 | RBAC/resource discovery burst (10-read burst / 30s) | MEDIUM | K8s audit log |

Four techniques — T1059, T1021, T1548, T1611 — carry **no scope
exclusion** (no pod-name or namespace exemption) by deliberate design. An
earlier iteration of the system exempted pods matching a "known-safe"
name pattern; this was removed after identifying it as a genuine bypass
(an attacker can trivially name a malicious pod `legitimate-app-evil`).
The precision cost of this decision is measured honestly in Section
VI-A rather than concealed through a contrived benign control.

**TABLE III. Correlated attack chains (all CRITICAL severity), 120-second
sliding correlation window.**

T1059→T1552 · T1021→T1059→T1552 · T1059→T1610→T1552 ·
T1059→T1548→T1611 · T1611→T1552

---

## V. Evaluation Methodology

### A. Testbed

3-node `kind`-provisioned Kubernetes cluster (1 control-plane, 2 worker
nodes), Kubernetes v1.30.0, Tetragon v1.7.0, Linux kernel 6.6. All
experiments were executed against this live cluster; no result in this
paper is derived from simulation, mocked telemetry, or synthetic data.

### B. Research Questions

- **RQ1 (Detection Accuracy).** For each of the 11 techniques, what are
  CAGE's precision, recall, and F1, and how does behavior differ between
  techniques with and without a scope exclusion? → Section VI-A.
- **RQ2 (Cross-Layer Necessity).** Does any single telemetry source
  (eBPF-only or audit-log-only) achieve full coverage of the 11
  techniques, or is fusion structurally required? → Section VI-B.
- **RQ3 (Chain Reliability).** Does the chain correlator reliably
  re-detect independent instances of the same multi-step attack against
  the same workload, validating the episode-scoped re-arm design? →
  Section VI-C.
- **RQ4 (Evasion Boundary).** For CAGE's threshold-based detectors, where
  exactly does the detection/evasion boundary sit relative to the
  documented default thresholds? → Section VI-D.

### C. Statistical Treatment

All detection-rate figures report **Wilson score confidence intervals**
rather than the normal (Wald) approximation, because Wilson intervals
remain well-behaved at the sample sizes used here and at the 0%/100%
observed rates that occur throughout this evaluation, where the Wald
interval degenerates to zero width and misrepresents the true
uncertainty.

### D. Benign-Control Honesty

Not every technique admits a meaningful benign near-miss. Creating a
privileged pod, granting cluster-admin, and issuing an RBAC-discovery
burst are inherently suspicious *at the API level* — there is no
legitimate version of "create a privileged pod" that looks different
from the audit log's point of view. For T1496, T1613, T1548-PRIV-POD,
and T1548.005 we report recall only; a contrived benign control for
these would test nothing real, and we say so explicitly rather than
omit the caveat.

---

## VI. Results

### A. RQ1 — Detection Accuracy (Table IV / Fig. 5)

N=10 attack trials and, where a meaningful control exists, N=10 matched
benign trials, live cluster, fused configuration (220 total trials).

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

† No meaningful benign control exists (Section V-D); precision not
computed for these four rows.

Recall is 100% across all 11 techniques with a 95% confidence floor of
72.2% at this sample size — every attack trial was detected, in every
trial, with no exceptions. Precision divides the technique set exactly
along the design boundary stated in Section IV-C: the four techniques
with no scope exclusion (T1059, T1021, T1548, T1611) show precisely 50%
precision because they correctly fire on the matched benign action as
well as the attack action; the three techniques with genuine behavioral
discrimination in this table (T1552, T1610, T1499) show 100% precision.

**Detection latency** falls into two clusters. Audit-log-sourced
detections and the Tetragon capability-check (T1611) resolve in 0-4
seconds. Several Tetragon-sourced detections (T1059, T1548, T1499,
T1496, T1610) resolve in 26-30 seconds — a previously root-caused,
connection-age-dependent delivery delay internal to Tetragon's own event
streaming client, confirmed via direct inspection of each event's
embedded capture timestamp to originate between eBPF capture (fast,
~3.5s) and the event's delivery to the consuming client, not within
CAGE's own processing.

### B. RQ2 — Cross-Layer Necessity (Table V / Fig. 3-4)

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
Section I with controlled, live-cluster measurement rather than
architectural argument alone.

### C. RQ3 — Chain Correlation Reliability (Table VI-C / Fig. 8)

N=10 trials per chain, all 5 documented chains, each trial pair
separated by >120s (exceeding the correlation window) to force
genuinely independent episodes, and each chain-type block separated from
the next by the same margin, since several chains share overlapping
trigger actions (Section VII discusses a live-discovered timing pitfall
here). 50 total trials, live cluster, current (fixed) episode-scoped
dedup logic.

**TABLE VI-C. Chain re-detection across independent episodes.**

| Chain | Fired / N |
|---|---|
| T1059→T1552 | 10/10 |
| T1021→T1059→T1552 | 10/10 |
| T1059→T1610→T1552 | 10/10 |
| T1059→T1548→T1611 | 10/10 |
| T1611→T1552 | 10/10 |

Every documented chain re-fires reliably across 10 independent episodes
each, with zero missed detections (50/50). This directly validates the
episode-scoped re-arm design described in Section IV-B: had the earlier,
fire-once-forever dedup behavior (Section VII, defect 1) still been
present, at most the *first* trial of each chain would have fired and
every subsequent trial against the same long-lived pod would have been a
false negative — the empirical signature of that defect class is
precisely a 1/10 result, not the 10/10 observed here.

### D. RQ4 — Evasion Boundary Characterization (Table VII / Fig. 10)

N=10 trials per boundary per technique, default thresholds, live cluster.
For T1610 and T1613, "just under" is exactly one unit below the
documented default threshold; for T1499, "just under" uses a
deliberately wider margin (15 versus the threshold of 25) rather than
exactly 24, for a reason reported honestly in Section VII rather than
concealed: live measurement of the exact per-invocation process-count
overhead of the attack-firing helper proved unreliable across repeated,
carefully-spaced trials, and a defensible-but-imprecise boundary claim
was judged preferable to an exact-sounding one the evidence did not
actually support.

**TABLE VII. Evasion boundary results, default thresholds.**

| Technique | Just under threshold | At threshold |
|---|---|---|
| T1610 (threshold 5) | 0/10 fired | 10/10 fired |
| T1499 (threshold 25) | 0/10 fired | 10/10 fired |
| T1613 (threshold 10) | 0/10 fired | 10/10 fired |

All three threshold-based detectors show the same clean pattern: an
attacker who knows the default threshold and stays under it evades
detection with certainty (0/10 across 30 total sub-threshold trials);
an attacker who reaches the threshold is caught with equal certainty
(10/10 across 30 total at-threshold trials). We report this as a
measured, disclosed property of a threshold-based detector (Section III)
rather than as a weakness discovered post hoc — the threat model
explicitly scopes this boundary as known and deliberately characterized,
and this experiment is that characterization.

---

## VII. Lessons from Live-System Evaluation

Several real defects were found only by executing the evaluation against
live infrastructure, not by code review or testing against synthetic
data:

1. A fork-bomb detector (T1499) whose deduplication state was never
   cleared once set, meaning the rule could fire at most **once** for a
   given pod's entire lifetime — a genuine detection gap for any
   workload subject to more than one such burst, not merely a test
   artifact. Fixed by adding the same episode-scoped re-arm logic already
   used by the chain correlator (Section IV-B).
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

This experience was not unique to this evaluation. The companion
systems/performance evaluation for this project (latency, resource
overhead, polling scalability, and fault-tolerance testing, reported
separately) independently encountered and fixed two live-execution-only
defects of its own — both traced to process-identifier ambiguity
silently corrupting CPU/RSS resource-overhead and fault-recovery
measurements — using the same "found only by running it for real"
pattern. Two independent evaluation efforts on the same codebase, testing
different subsystems, each surfaced multiple defects invisible to code
review; neither found the other's defects by inspection either. We
surface this not as an incidental footnote but as a methodological claim:
for systems whose correctness depends on multi-source event timing and
cross-process state — dedup flags, correlation windows, alert buffers,
or process-identity bookkeeping — static analysis and unit-level testing
are necessary but not sufficient, and an evaluation pipeline that never
executes against the live target system risks reporting fabricated
confidence.

---

## VIII. Limitations and Threats to Validity

- **Cluster scale.** A single-control-plane, two-worker `kind` cluster is
  not a production-scale multi-node topology; detection latency and
  ablation results may not generalize unchanged to clusters several
  orders of magnitude larger.
- **Kernel/BTF dependency.** T1610 (network lateral movement) requires a
  BTF-enabled kernel (5.10+); confirmed functional on kernel 6.6, cross-
  environment portability (e.g., managed Kubernetes offerings with
  restricted kernel access) not independently verified.
- **T1021 scope.** T1021 carries no scope exclusion at all, flagging
  every `kubectl exec` including routine administrative access — an
  accepted, documented precision cost (Section IV-C, VI-A), not an
  oversight, but one that would need revisiting for a production
  deployment with a high baseline rate of legitimate `kubectl exec`
  traffic.
- **Sample size.** N=10 per condition narrows the 95% CI to a floor of
  72.2% at 10/10 — a substantial improvement over pilot N=2-3 data, but
  a larger N would further tighten intervals, particularly relevant near
  any future severity- or threshold-boundary claims.
- **T1499 evasion-boundary precision.** RQ4's T1499 result uses a
  comfortably-under-threshold value (15 versus the threshold of 25)
  rather than an exact threshold-minus-one boundary, for the reason
  reported in Section VII: the exact process-count overhead of the
  attack-firing mechanism itself proved difficult to pin down reliably in
  live testing. T1610 and T1613's boundaries are exact.
- **Deferred experiments.** An old-code-versus-new-code comparison for
  the chain-correlation fix (Section IV-B), and a threshold-sweep
  experiment varying detection thresholds across multiple values rather
  than only default-versus-boundary, were both explicitly descoped from
  this evaluation cycle for time and are not included in this paper's
  results. Neither affects the validity of the results that are
  included; both would add depth to, respectively, Section VI-C and
  Section VI-D.

---

## IX. Conclusion

This paper presented CAGE, a cross-layer Kubernetes runtime security
system that fuses eBPF telemetry with the Kubernetes audit log via a
pod-identity-keyed correlator, and evaluated it entirely on live
infrastructure against four explicit research questions. Per-technique
recall reached 100% across all 11 detected MITRE ATT&CK techniques
(RQ1). A 330-trial ablation study produced the paper's central empirical
result: a perfectly complementary 0%/100% detection split across 220
single-source trials, recovered to 100% only once both telemetry sources
were fused, with no single source covering more than six of the eleven
techniques (RQ2) — direct, controlled evidence that cross-layer fusion is
not an incremental improvement over single-source detection for this
technique set, but a structural requirement for full coverage. All five
documented attack chains re-armed and re-fired correctly across ten
independent episodes each, validating the system's episode-scoped
correlation design against the specific failure mode — permanent,
fire-once dedup — that an earlier version of the codebase actually
exhibited (RQ3). CAGE's three threshold-based detectors each drew a
clean, disclosed line between certain evasion and certain detection at
their documented default thresholds (RQ4). Beyond these results, this evaluation effort surfaced multiple real
detection-logic and evaluation-tooling defects that static analysis
alone did not catch — a finding that we believe generalizes beyond this
system to any runtime security tool whose correctness depends on
cross-process state and multi-source event timing: such systems should
be evaluated by running them, not only by reading them.

---

## References

*(Citations verified via web search this session against publicly
available sources; exact page ranges/DOIs should be cross-checked against
final published versions before submission — flagged inline where a
detail was not independently confirmed.)*

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
against IEEE Xplore record before submission.)*

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
Reports that newly created clusters on major managed Kubernetes offerings
receive a first attack attempt within 18–28 minutes of deployment,
based on analysis of over 200,000 cloud accounts. [Online]. Available:
https://www.wiz.io/reports/kubernetes-security-report-2025

*(Additional references needed before submission: at least 15-20 more
citations are standard for an IEEE Access paper of this scope — MITRE
ATT&CK framework citation, Kubernetes/container security survey papers,
eBPF background citation, and any papers on Wilson confidence intervals
or the statistical methods used. This reference list currently covers
only the direct related-work comparison; a full literature review pass
is recommended before submission.)*
