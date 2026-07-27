## Table 6 — Related-Work Feature Comparison

Qualitative comparison, not a quantitative benchmark (see the note below
the table). K8NTEXT, UNICORN, PACED, and P4Control's entries are carried
forward from this project's own `DEMO_GUIDE.md`, which the wider paper
draft already committed to; Falco and vanilla Tetragon are added here
since `EVALUATION_PLAN.md` names both as natural comparison points and
they are the two most directly relevant deployed tools (Falco as the
dominant open-source K8s runtime-security tool, vanilla Tetragon as the
single-source baseline CAGE itself is built on top of and extends).

| System | Telemetry Sources | Multi-Hop Chain Detection | K8s Pod-Identity Correlation | Live Attack-Graph Dashboard | False-Positive Mitigation |
|---|---|---|---|---|---|
| K8NTEXT | eBPF only | 2-hop | — | — | Not specified |
| UNICORN | eBPF + provenance graph | 2-hop | — | — | Provenance-graph anomaly scoring |
| PACED | K8s audit log only | 1-hop | — | — | Not specified |
| P4Control | Network (P4) only | 1-hop | — | — | Not specified |
| Falco | eBPF/kernel-module (syscalls) | None (single-event rules) | Partial (K8s metadata enrichment on syscall events, not a first-class correlation key) | Not built-in (Falcosidekick/UI is a separate, optional component) | Static rule tuning; no built-in behavioral-burst thresholds |
| Vanilla Tetragon | eBPF only (process exec, network, file, capabilities) | None (per-policy alerts, no cross-event correlation) | Native K8s metadata on events, but not used as an explicit cross-source join key (there is only one source) | Hubble UI (network-flow visualization; not an attack-chain/kill-chain view) | Per-policy filtering only |
| **CAGE** | **eBPF (Tetragon) + K8s audit log + pod-UID watch** | **3-hop, 5 documented chain types** | **Pod UID as the explicit correlation key across all three sources** | **Yes — canvas attack graph, kill-chain stepper, MITRE matrix, per-source health status** | **Namespace-scope exclusion (not name-based — a name-based version was found and removed as a real evasion vector, see README.md), scan-burst thresholds (T1610), remote-exec correlation windows (T1059)** |

**This table is qualitative, not a quantitative benchmark — flagged
explicitly, not silently implied.** No side-by-side measurement (e.g.,
running Falco or vanilla Tetragon against the same E1/E2 attack set in
this same cluster and comparing precision/recall/latency numbers
directly) has been performed. `EVALUATION_REVIEW.md` recommended this as
a cheap addition (vanilla Tetragon specifically, since it's already
running as CAGE's own eBPF backend) — it was not done here because it
depends on the same ablation-mode infrastructure (`ABLATION_MODE=
tetragon_only`) that Person A's E2 experiment owns, and duplicating or
running ahead of that work was explicitly out of scope for this pass.
This remains the single most valuable follow-up to strengthen the
Related Work section from qualitative to quantitative.
