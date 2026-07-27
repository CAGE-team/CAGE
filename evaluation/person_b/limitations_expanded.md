# Expanded Limitations / Threats to Validity

Consolidates the limitations already documented in `README.md` and
`DEMO_GUIDE.md` with the four items `EVALUATION_REVIEW.md` flagged as
missing from `EVALUATION_PLAN.md`'s original §5.7 outline. Written as
manuscript-ready prose, organized by category, for direct inclusion in
the paper's Limitations / Threats to Validity section.

## Environment and deployment scope

- **Single-node `kind` cluster, not a production multi-node deployment.**
  All experiments in this evaluation ran on one three-node `kind` cluster
  (1 control-plane + 2 workers) on a single machine. The core detection
  design — pod-UID correlation via the K8s watch API — does not assume a
  single node, but no multi-node validation has been performed.
- **Audit log access requires directly patching the kube-apiserver
  manifest** (`kind-config.yaml`'s `kubeadmConfigPatches`), which in a
  managed or production cluster is normally configured at cluster-creation
  time rather than after the fact. Untested against a managed control
  plane (EKS/GKE/AKS) where this may not be operator-controllable at all.
- **T1610 (network) detection needs a BTF-enabled kernel (Linux 5.10+).**
  Confirmed working on this project's WSL2 kernel (6.6.87.2); WSL2's
  CO-RE struct-layout handling has, in other environments, blocked T1610
  entirely. Not portable as-is to every kernel/host combination.
- **Virtualization-environment generalizability (newly added).** Every
  latency and overhead number in this evaluation (E4, E5, E6) was measured
  on a `kind` cluster running inside a WSL2 virtual machine, not on
  bare-metal Kubernetes. The *relative* findings — audit-log detection
  consistently faster than Tetragon-sourced detection, resource overhead
  staying bounded under load — plausibly generalize, since they reflect
  differences in the detection pipelines themselves rather than
  environment-specific artifacts. The *absolute* numbers (the ~30s
  Tetragon delivery lag in particular; see the Performance section) may
  not transfer directly to bare-metal, where the `kubectl exec`/gRPC
  streaming path this project's investigation implicates would not cross
  a virtualization boundary. This evaluation does not test bare-metal
  Kubernetes and cannot rule out that possibility.

## Detection design scope

- **T1610's rule now requires a scan-like burst** (5+ distinct destination
  pods within 10 seconds) rather than firing on a single ordinary
  connection, closing a previously-documented high-false-positive-rate
  issue on benign pod-to-pod traffic.
- **T1021 (`_check_t1021` in `causal_graph.py`) has no scope exclusion at
  all** — not even the namespace-level check every other behavioral rule
  has. It fires on any `kubectl exec` into any pod, including routine
  administrative access into a `kube-system` component. Whether this is
  intentional (all remote exec is inherently worth flagging) or should
  receive the same namespace exclusion as the other rules remains an open
  design question.
- **120-second correlation window** — an attack chain must complete
  within that window to be linked into a CRITICAL chain alert; a
  slower-paced attack spanning more than 120 seconds between hops would
  not be correlated, though the individual per-technique alerts would
  still fire independently.

## Evaluation methodology (newly added, from `EVALUATION_REVIEW.md`)

- **Synthetic, non-adaptive attack scripts.** Every trial in this
  evaluation (E1–E3, E7's per-technique attacks, and the attack commands
  E4/E8 reuse to generate real detections) is a fixed, known, non-evasive
  command sequence executed by the researchers themselves — not
  red-team-style obfuscation, renamed binaries, split/staggered timing
  designed to straddle detection windows, or any other adversarial
  evasion strategy. The detection rates and latency figures in this paper
  characterize CAGE's behavior against this specific, disclosed attack
  set. They are not evidence of robustness against an adaptive adversary
  who has read this paper and is deliberately trying to evade these exact
  rules — no such testing was performed.
- **No adversarial evasion testing beyond the one bypass found and fixed
  during development.** The namespace-only scope-exclusion design (see
  README.md) was adopted specifically because an earlier, name-based
  whitelist was found to be a real evasion vector during this project's
  own development — but that discovery was incidental (found while
  auditing the code for hardcoded assumptions), not the product of a
  systematic red-team exercise. Other evasion strategies (timing,
  fragmentation across the correlation window, binary renaming where the
  detection rule matches on binary path) have not been systematically
  tested.
- **Small-sample statistical uncertainty.** Trial counts throughout this
  evaluation (N=8–20 for most Person-B experiments before scaling, single
  runs for some fault-injection scenarios before replication) are bounded
  by practical session time, not by a formal power analysis. Where N is
  small, point estimates (detection rates, mean latencies) carry real
  uncertainty that should be read alongside the confidence intervals
  reported alongside them, not as exact values.
- **No quantitative baseline comparison.** `Table 6` (related-work
  comparison) is qualitative — feature comparison against systems
  described in their own publications, not a head-to-head measurement in
  this project's own cluster. No other tool (Falco, vanilla Tetragon
  without CAGE's correlation layer) was run against the same attack set
  to produce directly comparable precision/recall/latency numbers in this
  evaluation. `EVALUATION_REVIEW.md` identifies a low-cost way to close
  part of this gap (vanilla Tetragon alone, since it is already running
  as CAGE's own eBPF backend) as the highest-value follow-up.

## Evaluation infrastructure reliability (found during full-scale data collection)

- **Stale-process PID ambiguity silently corrupted two full-scale
  measurements before being caught.** This evaluation's own tooling
  resolves the CAGE server's PID via `pgrep -f "src/server.py"` in
  several places, to either read its log file or sample its CPU/RSS. This
  pattern also matches the `bash -c "... nohup python3 src/server.py ...
  & disown"` wrapper used to background a server restart; when that
  wrapper failed to exit promptly (traced to the wrapper inheriting the
  parent script's stdin instead of being fully detached), its lower PID
  sorted before the real server's and was silently picked instead. This
  corrupted an entire full-scale E8 run (13/15 fault-recovery trials
  recorded a false "never recovered") and a full-scale E5 run (measured
  0.0% CPU / 1.7MB RSS for 20 minutes — the wrapper process, not the
  server). Both were caught by comparing results against physically
  plausible ranges and pilot-scale baselines, fixed by anchoring the
  pattern to `^python3 src/server.py`, and re-run clean. Reported here
  because the general lesson — that this specific WSL/`kind` environment
  can leave restart-wrapper processes alive in ways that confuse
  substring-based process matching — is a property of the environment
  this evaluation ran in, not just a one-off script bug, and future
  extensions of this evaluation suite should assume any PID-resolution-by
  -pattern code needs the same anchoring discipline.
- **Connection-age sweep result is an open question, not a resolved
  finding.** Two independent runs of the identical connage-sweep
  methodology, at different scales, produced contradictory results (see
  `RESULTS.md`'s E4 section for the full comparison). The full-scale run
  shows evidence of contamination by a draining event backlog immediately
  after server restart; the fix (wait for the log to go quiet before
  starting the age clock, rather than a fixed warmup) is identified but
  not implemented or re-tested within this evaluation's scope. This paper
  relies on the N=20 distribution test (unaffected, since it does not
  restart the server between trials) for its primary latency claim, and
  explicitly does not claim to have resolved the connection-age question
  either direction.

## Systems characterization (not fixed, reported honestly)

- **Tetragon delivery latency.** A live investigation (see README.md and
  `evaluation/person_b/RESULTS.md`'s E4 section) found Tetragon-sourced
  detections consistently take roughly 30 seconds end-to-end on this
  project's cluster, and that this effect is **not** the connection-age
  effect it was originally hypothesized to be — a controlled sweep found
  latency flat at ~30s regardless of connection age from 7 to 127
  seconds. The mechanism was not conclusively root-caused within this
  project's scope; an attempted fix (periodically cycling the consumer's
  subprocess connection) was implemented, tested live, found to introduce
  real event loss without reliably reducing latency, and reverted. The
  60-second detection-wait windows used throughout this evaluation's own
  scripts are a measurement-methodology accommodation for this effect,
  not a fix to it. Any application treating CAGE's Tetragon-sourced
  alerts as near-real-time should be aware of this finding.
