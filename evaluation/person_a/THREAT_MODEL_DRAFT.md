# Threat Model & Assumptions — Draft (Gap 5)

Draft for you to review and adapt into the paper (likely Section 3, right
before or as part of the system design section). Grounded in what this
codebase actually assumes, traced from the real implementation, not
generic boilerplate.

## In scope

CAGE detects an attacker who has already obtained code execution inside
one pod (via a vulnerable application, a supply-chain compromise, or a
misconfigured/leaked credential) and attempts to escalate from that
foothold: spawning shells, moving laterally to other pods, reading
Kubernetes secrets, escalating privileges inside or out of the container,
abusing RBAC, or degrading node resources. This matches the 11 MITRE
ATT&CK techniques in README.md's technique table.

## Trust assumptions (what CAGE relies on being honest)

- **The Linux kernel and eBPF subsystem are trusted.** Tetragon's
  detections depend on kernel-level hooks (`process_exec`, `tcp_connect`,
  `cap_capable` kprobes); an attacker with the ability to load their own
  eBPF programs, exploit a kernel vulnerability to blind existing hooks, or
  otherwise compromise the host kernel is out of scope. This is a common
  assumption for any eBPF-based defense — defeating it means defeating the
  detection substrate itself, not just CAGE's logic on top of it.
- **The Kubernetes API server and its audit log are trusted.** CAGE's
  second telemetry source is the API server's own audit log
  (`audit-policy.yaml`, tailed by `audit_log_consumer.py`). An attacker with
  control-plane-level access able to disable or tamper with audit logging
  before CAGE reads it is out of scope — this is a privilege level well
  beyond "compromised one workload pod."
- **CAGE's own process is trusted and not itself compromised.** No attempt
  is made to defend CAGE's correlator/dashboard process against an attacker
  who has already gained node-level or CAGE-process-level access; at that
  point the attacker could simply kill or blind the detector directly. (The
  system does defend against *infrastructure failures* affecting these
  components — see the fault-injection experiment, E8 — but that's
  reliability, not an adversarial threat.)

## Explicitly out of scope

- **Kernel/eBPF-blinding rootkits** (see above).
- **Supply-chain attacks that never trigger a detected technique** — e.g. a
  malicious dependency that reads environment variables and exfiltrates
  them without spawning a shell, making a flagged network connection, or
  touching the K8s API in a way any of the 11 rules watch for. CAGE detects
  *behavior*, not the initial compromise vector.
- **Attacks entirely within a single audit-log or eBPF event that individually
  looks identical to legitimate administrative activity** — see the
  Limitations section (T1021 has no scope exclusion at all; any `kubectl
  exec`, legitimate or not, is flagged, which is a precision cost, not a
  recall gap).
- **Multi-cluster or cross-cluster lateral movement** — CAGE's pod UID cache
  and correlation window are scoped to a single cluster's K8s API.

## Known, deliberately-tested boundary (not a gap — measured directly)

Several detection rules use fixed numeric thresholds
(`CONNECTION_BURST_THRESHOLD=5`, `FORK_BOMB_EXEC_THRESHOLD=25`,
`RBAC_DISCOVERY_THRESHOLD=10`, and the 120-second chain-correlation window).
An attacker who knows these values and deliberately stays under them can
evade the specific rule they're tuned against — this is not a hidden
weakness; E9 (evasion boundary testing, see EVALUATION_PLAN.md/
EVALUATION_REVIEW.md) measures exactly where that boundary sits and reports
it directly in the paper rather than leaving it implicit. This is the
correct way to state a threshold-based detector's limits: characterized,
not assumed away.
