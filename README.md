# CAGE — Cross-Layer Attack Graph Engine

Kubernetes runtime security system that fuses eBPF telemetry, Kubernetes
audit logs, and pod identity to detect multi-step lateral-movement attacks
in real time, with a live SOC-style dashboard.

Evaluated entirely on live infrastructure (not simulation) across eight
research questions spanning detection quality and systems characteristics.
Written up as an IEEE Access manuscript — see [Paper](#paper) below.

## What it does

Most tools watch one signal (syscalls, or network, or API calls). CAGE
watches three sources at once and correlates them by pod UID to catch
attack **chains**, not just isolated events.

**Detections (MITRE ATT&CK):**

| Technique | Alert | Severity | Source |
|---|---|---|---|
| T1059 | Shell spawned inside a pod | MEDIUM | Tetragon eBPF |
| T1021 | Remote exec (`kubectl exec`) | MEDIUM | K8s audit log |
| T1610 | Pod-to-pod network lateral movement | MEDIUM | Tetragon kprobe |
| T1552 | Secret access via K8s API | HIGH | K8s audit log |
| T1611 | Container escape (dangerous capability / escape binary) | HIGH | Tetragon eBPF |
| T1548 | Privilege escalation attempt inside a container | HIGH | Tetragon eBPF |
| T1548-PRIV-POD | Privileged pod created | HIGH | K8s audit log |
| T1548.005 | Cluster-admin / wildcard RBAC grant | CRITICAL | K8s audit log |
| T1496 | Cryptomining process signature | HIGH | Tetragon eBPF |
| T1499 | Fork-bomb-like exec burst (resource DoS) | HIGH | Tetragon eBPF |
| T1613 | RBAC / resource discovery burst | MEDIUM | K8s audit log |

**Correlated attack chains (CRITICAL):**
- T1059 → T1552 (shell → secret access)
- T1021 → T1059 → T1552 (remote exec → shell → secret access)
- T1059 → T1610 → T1552 (shell → network pivot → secret access)
- T1059 → T1548 → T1611 (shell → priv-esc → container escape)
- T1611 → T1552 (escape → secret access)

Chains are correlated per pod UID inside a 120-second sliding window, with
episode-scoped deduplication: a chain re-arms once its constituent legs are
no longer all satisfied, so a genuinely later, independent incident on the
same long-lived pod is reported again rather than suppressed.

## Architecture

```
Tetragon eBPF stream ──┐
                        ├─→ shared queue → CausalGraph → alerts → SSE → dashboard
K8s Audit Log stream ──┤
Network Monitor ───────┘
        ↑
   Pod UID Cache (K8s watch API — the correlation key across all sources)
```

## Codebase

```
src/
├── uid_resolver.py         — live pod identity cache (K8s watch API)
├── tetragon_consumer.py    — eBPF process_exec / kprobe event stream parser
├── audit_log_consumer.py   — K8s audit log tailer/parser
├── network_monitor.py      — pod-to-pod TCP connection tracking (T1610),
│                              concurrent thread-pool polling
├── causal_graph.py         — detection rules + chain correlation engine
├── correlator.py           — orchestrator wiring sources → causal graph
└── server.py                — Flask API + SSE streaming backend, incl.
                                GET /api/health (per-source last-seen event
                                timestamp, event count, subprocess liveness —
                                observability only, doesn't touch detection)

dashboard/
├── index.html               — multi-page dashboard shell (sidebar nav, hash
│                               routing): Overview, Attack Graph, Alerts,
│                               Chains, MITRE Matrix, Pods, Timeline, Health
└── app.js                   — dashboard logic: canvas attack graph, alert
                                feed/table, chain history, sparkline, and
                                the Health page (reads GET /api/health above)

k8s/
├── tcp-connect-policy.yaml       — Tetragon TracingPolicy for T1610
└── capability-check-policy.yaml — Tetragon TracingPolicy for T1611/T1548

evaluation/
├── latex/                  — IEEE Access manuscript (main.tex, main.pdf)
├── person_a/                — detection-quality experiments (E1, E2, E3, E9),
│                               scripts, raw CSVs, plots, tables
├── person_b/                 — systems-characteristics experiments (E4, E5,
│                               E6, E8), scripts, raw CSVs, plots, tables
└── figures/                 — hand-authored architecture/pipeline diagrams
                                (source .svg alongside rendered .pdf/.png)

DEMO_GUIDE.md                 — full walkthrough for presenting the project
restart_cage.sh               — rebuilds the kind cluster, Tetragon, and the
                                audit-log-patched API server from a clean state
```

## Setup

1. Install Docker Desktop, enable WSL2 integration
2. Install `kind`, `kubectl`, `helm` inside Ubuntu/WSL2
3. `kind create cluster --config kind-config.yaml --name cage`
4. `helm install tetragon cilium/tetragon -n kube-system`
5. `pip install flask flask-cors kubernetes networkx matplotlib --break-system-packages`
6. Apply Tetragon policies: `kubectl apply -f k8s/tcp-connect-policy.yaml -f k8s/capability-check-policy.yaml`
7. Enable K8s audit logging using `audit-policy.yaml` (patch kube-apiserver, see `DEMO_GUIDE.md` Step 4)

Or, to rebuild the whole environment from a clean state in one step:
```bash
./restart_cage.sh
```

## Run

```bash
python3 src/server.py       # starts correlator + Flask/SSE backend
# open http://localhost:5000 for the live dashboard
```

Standalone component tests:
```bash
python3 src/tetragon_consumer.py   # live tagged event stream
python3 src/uid_resolver.py        # pod UID cache smoke test
```

For the full attack-trigger walkthrough and how to explain the dashboard
during a demo, see `DEMO_GUIDE.md`.

## Evaluation

Full-scale results across eight research questions, entirely on live
infrastructure. Headline numbers (see the paper for full methodology,
confidence intervals, and discussion):

| RQ | Question | Result |
|---|---|---|
| RQ1 | Per-technique detection accuracy (E1) | 100% recall across all 11 techniques (180 trials) |
| RQ2 | Telemetry-source ablation (E2) | Perfectly complementary split across 330 trials — every technique fires at 0% under exactly one single-source configuration and 100% under fusion; no single source covers more than 6 of 11 |
| RQ3 | Chain-correlation reliability (E3) | All 5 documented chains re-fire correctly across 10 independent episodes each (50/50) |
| RQ4 | Evasion boundary characterization (E9) | Deterministic 0/10 just under threshold, 10/10 at threshold, across all 3 threshold-based detectors |
| RQ5 | Detection latency (E4) | Audit-log-sourced detections: 0.19s mean. eBPF-sourced (Tetragon) detections: 27.96s mean plateau |
| RQ6 | Resource overhead (E5) | ~3.2% CPU, ~135MB RSS, flat under active attack load |
| RQ7 | NetworkMonitor polling scalability (E6) | Cycle time flat (4.68–5.35s) across 1–16 monitored scan-target pods, after a concurrency fix |
| RQ8 | Fault injection and recovery (E8) | 15/15 functional recoveries across 3 injected fault scenarios, no operator intervention |

Raw CSVs, generation scripts, and full per-experiment write-ups live under
[`evaluation/person_a/`](evaluation/person_a/) (detection quality) and
[`evaluation/person_b/`](evaluation/person_b/) (systems characteristics).
See [`evaluation/README.md`](evaluation/README.md) for the reproducibility
overview, or the paper's Appendix A for a full artifact inventory.

## Known limitations

The paper's Limitations and Threats to Validity section is the canonical,
fully detailed version. In brief:

- Single-control-plane, two-worker `kind` cluster inside a WSL2 VM, not a
  production-scale multi-node bare-metal deployment.
- T1610's kprobe-based path requires a BTF-enabled kernel; confirmed
  functional on kernel 6.6, not independently verified across every managed
  Kubernetes offering.
- CAGE authenticates with the same local kubeconfig used to administer the
  cluster in this evaluation, rather than a dedicated minimally-scoped
  ServiceAccount; its actual behavior is read-only by design, but the
  runtime credential is broader than the architecture requires.
- T1021 (`kubectl exec`) has no namespace scope exclusion at all, by
  deliberate design — it flags every remote exec, including routine
  administrative access, since excluding infrastructure namespaces would
  also exclude a real attacker's own remote-exec session.
- Every attack used in evaluation is a fixed, disclosed, non-adaptive
  command sequence; robustness against an adversary actively trying to
  evade these exact rules is characterized only at the one boundary RQ4
  measures directly.
- The comparison against related systems (Falco, Tetragon, K8NTEXT, PACED,
  UNICORN, KAIROS, P4Control) is qualitative, built from each system's own
  published description, not a head-to-head measurement in this cluster.

## Paper

The full IEEE Access manuscript lives in
[`evaluation/latex/`](evaluation/latex/) (`main.tex`, compiled `main.pdf`).

**CAGE: A Cross-Layer Attack Graph Engine for Real-Time Kubernetes Runtime
Security** — Nagasundari S, Arundhathi K, Prajin R. Department of CSE,
Center for Information Security, Forensics and Cyber Resilience, PES
University, Bengaluru, India.

## Status

- [x] Environment: kind + Tetragon
- [x] Pod UID resolver + Tetragon consumer
- [x] Causal graph + MITRE correlation rules (11 techniques, 5 chains)
- [x] Live SOC dashboard (attack graph, alert feed, MITRE legend, sparkline)
- [x] Container escape / privilege escalation / resource abuse / RBAC abuse detection
- [x] Full-scale live-cluster evaluation, RQ1–RQ8 (see Evaluation above)
- [x] IEEE Access manuscript written, formatted, and submission-ready
- [ ] Multi-node cluster validation (tracked as future work in the paper)
- [ ] Head-to-head quantitative comparison against vanilla Tetragon (tracked
      as future work in the paper)
