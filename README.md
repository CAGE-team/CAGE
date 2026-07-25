# CAGE — Cross-Layer Attack Graph Engine

Kubernetes runtime security system that fuses eBPF telemetry, Kubernetes
audit logs, and pod identity to detect multi-step lateral-movement attacks
in real time — with a live SOC-style dashboard.

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

Chains are correlated per pod UID inside a 120-second sliding window.

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
├── uid_resolver.py        — live pod identity cache (K8s watch API)
├── tetragon_consumer.py    — eBPF process_exec / kprobe event stream parser
├── audit_log_consumer.py   — K8s audit log tailer/parser
├── network_monitor.py      — pod-to-pod TCP connection tracking (T1610)
├── causal_graph.py         — detection rules + chain correlation engine
├── correlator.py           — orchestrator wiring sources → causal graph
└── server.py               — Flask API + SSE streaming backend, incl.
                               GET /api/health (per-source last-seen event
                               timestamp, event count, subprocess liveness —
                               observability only, doesn't touch detection)

dashboard/
├── index.html               — multi-page dashboard shell (sidebar nav, hash
│                               routing): Overview, Attack Graph, Alerts,
│                               Chains, MITRE Matrix, Pods, Timeline, Health
└── app.js                   — dashboard logic: canvas attack graph, alert
                                feed/table, chain history, sparkline, and
                                the Health page (reads GET /api/health below)

k8s/
├── tcp-connect-policy.yaml       — Tetragon TracingPolicy for T1610
└── capability-check-policy.yaml — Tetragon TracingPolicy for T1611/T1548

week4/                        — evaluation: ablation study, benign controls,
                                latency capture, scenario scripts, metrics, plots
run_ablation.py               — fires attacks against a running server for a
                                given ABLATION_MODE and logs fired/not-fired
week4/run_benign_controls.py  — reproducible benign/false-positive trials,
                                writes results_benign_v2.csv (see Evaluation)
plot_graph2.py                — attack-vs-benign alert rate bar chart
DEMO_GUIDE.md                  — full walkthrough for presenting the project
```

## Setup

1. Install Docker Desktop, enable WSL2 integration
2. Install `kind`, `kubectl`, `helm` inside Ubuntu/WSL2
3. `kind create cluster --config kind-config.yaml --name cage`
4. `helm install tetragon cilium/tetragon -n kube-system`
5. `pip install flask flask-cors kubernetes networkx matplotlib --break-system-packages`
6. Apply Tetragon policies: `kubectl apply -f k8s/tcp-connect-policy.yaml -f k8s/capability-check-policy.yaml`
7. Enable K8s audit logging using `audit-policy.yaml` (patch kube-apiserver — see `DEMO_GUIDE.md` Step 4)

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

**Detection eval (5 trials, full chain T1021→T1059→T1552):** 100% detection
rate, 0 false positives, ~7s average detection latency (cold start), ~4.7s
steady state. Details in `DEMO_GUIDE.md`.

**Ablation study** (`week4/results_ablation.csv`) — isolates which telemetry
source each technique actually needs:

| Condition | T1059 | T1021 | T1552 | T1610 |
|---|---|---|---|---|
| Tetragon only | 9/10 | 0/10 | 0/10 | 10/10 |
| Audit log only | 0/10 | 10/10 | 10/10 | 0/10 |
| Fused (both) | 9/10 | 10/10 | 10/10 | 10/10 |

This is the core evidence for the cross-layer design: T1059 and T1610 are
invisible to the audit log, T1021 and T1552 are invisible to eBPF — no
single source covers the full chain.

**Benign controls** (`week4/results_benign.csv`) — 10 trials each of benign
shell use, benign exec, benign privileged behavior, and benign pod-to-pod
traffic. T1059/T1021/T1548 controls: 0/10 false positives. **T1610 control:
10/10 fired** — the current network-lateral-movement rule does not yet
distinguish benign pod-to-pod traffic from an attack pattern and is a known
false-positive source, tracked as an open item below.

> **Reproducibility note on the above.** `results_benign.csv` predates this
> repo's reconciliation merge with no accompanying generation script or
> documented commands — only the four category names and their aggregate
> results survive. `week4/run_benign_controls.py` implements a new,
> explicitly-documented methodology against the current code and writes to
> `week4/results_benign_v2.csv`, leaving the original file untouched as
> historical, pre-whitelist-removal data.
>
> **Update (2026-07-25, latency root cause):** a follow-up investigation
> localized the ~28s Tetragon delivery lag (referenced above) precisely:
> it is **connection-age-dependent, not caused by CAGE's own code.**
> Redirecting `kubectl exec -n kube-system ds/tetragon -c tetragon --
> tetra getevents` straight to a file (bypassing tetragon_consumer.py
> entirely) delivered an event in ~150ms on a connection open only 3
> seconds — but the *identical* command, left running 35 seconds before
> firing the same attack, delivered the same kind of event ~30s late. The
> event's own Tetragon-embedded capture timestamp confirmed the eBPF
> capture itself was fast (~3.5s) — the ~30s gap was entirely between
> capture and the line becoming visible in `tetra getevents`' own stdout.
> This rules out kube-system event-volume noise (also tested and fixed
> separately — `tetragon_consumer.py`'s `_tag_event()` now filters
> `SYSTEM_NAMESPACES` at the source instead of only in
> `causal_graph.py`'s rule checks, cutting total event volume by ~77% on
> an idle cluster — but this did not change the latency), node/daemonset-pod
> routing mismatches (checked directly), and Python-side processing. It
> points to periodic output buffering inside `tetra getevents` itself that
> only manifests once the connection has been open a while — `tetra`
> exposes no CLI flag to control this, and `stdbuf` cannot help (it
> intercepts glibc's buffering, but `tetra` is a Go binary with its own
> internal I/O). A concrete, not-yet-implemented follow-up: periodically
> cycling `tetragon_consumer.py`'s subprocess connection (e.g. every ~20s,
> before it ages into the slow regime) instead of holding one connection
> open indefinitely — untested here due to the risk of event loss/
> duplication across a reconnect without further validation budget. The
> 60s eval-script timeouts (below) are a safe mitigation regardless of
> whether that follow-up is ever implemented.
>
> **Update (2026-07-25, whitelist removal):** a later change removed `causal_graph.py`'s
> pod-name-based whitelist entirely (it was a real detection bypass — an
> attacker could name their own pod `legitimate-app-evil` and evade
> T1059/T1611/T1548/T1496/T1499 detection outright). Scope exclusion is now
> namespace-only. That means T1059/T1021/T1548 have no pod-identity
> exemption left at all — verified live: `legitimate-app` now fires all
> three unconditionally, where it previously stayed silent for two of them.
> `run_benign_controls.py` and its category labels were updated to match
> (`T1059_unconditional` / `T1021_unconditional` / `T1548_unconditional` —
> renamed from `*_whitelisted`, since there is no longer a whitelist to
> test). A fresh live run confirmed the corrected script end-to-end:
> `T1059_unconditional` 2/2, `T1021_unconditional` 2/2, `T1548_unconditional`
> 2/2 — all fire every time, by design, not a regression — and
> **`T1610_benign` 0/2**, which is the one category with genuine behavioral
> discrimination (a 5-distinct-destination/10s burst, independent of pod
> identity) and is the actual answer to the open item below: the
> burst-threshold fix holds up against ordinary, non-scan-like pod-to-pod
> traffic. Run `python3 week4/run_benign_controls.py <server-logfile>` for
> the full 10-trial version.

## Known limitations

- Single-node `kind`/docker-desktop cluster, not a multi-node production setup.
- Audit log access requires directly patching the kube-apiserver manifest;
  in production this is normally set at cluster-creation time.
- T1610 (network) detection needs a BTF-enabled kernel (Linux 5.10+); WSL2's
  CO-RE struct-layout mismatch has, in some environments, blocked T1610
  entirely — confirmed working on kernel 6.6 here, but not portable as-is.
- T1610 previously had a high false-positive rate on benign pod-to-pod
  traffic (see benign controls above, captured before this fix). The rule now
  requires a scan-like burst (5+ distinct destination pods within 10s) instead
  of firing on a single ordinary connection. Re-validated with
  `week4/run_benign_controls.py` (see the reproducibility note above) — full
  10-trial confirmation still pending, tracked below.
- **T1610's poll-based detection path (`NetworkMonitor`) was silently
  non-functional until 2026-07-25.** Three independent bugs, found while
  investigating why a working T1610 burst wasn't firing: (1)
  `week4/scan-targets.yaml` — the manifest documented in `DEMO_GUIDE.md`
  for provisioning T1610 demo targets — deployed plain `ubuntu:latest`
  pods running `sleep infinity`, nothing listening on any port, so every
  demo attempt following the actual documented setup failed with
  connection-refused; fixed to `nginx:alpine`. (2) `NetworkMonitor`
  checked its monitored pods sequentially, one `kubectl exec` at a time —
  with enough pods, a full sweep's wall-clock time exceeded
  `CONNECTION_BURST_WINDOW_SECONDS` (10s), so a genuine 5-destination
  burst got split across separate sweeps and could never satisfy the
  threshold no matter how long connections were held open; fixed to
  check all monitored pods concurrently via a thread pool, keeping sweep
  time close to `poll_interval` regardless of pod count. (3) — the root
  cause once (1) and (2) were fixed and it *still* didn't fire —
  `NetworkMonitor`'s event dict used the field names `dst_pod`/`dst_uid`,
  but `causal_graph.py`'s `_check_t1610` reads `dst_pod_name`/
  `dst_pod_uid` (the names `tetragon_consumer.py`'s own network-event
  producer already used correctly); every event `NetworkMonitor` ever
  produced was silently rejected by the rule. All three verified live: a
  5-pod burst now fires T1610 on the first attempt. This does not affect
  T1610 detections via Tetragon's `tcp_connect` kprobe path
  (`tetragon_consumer.py`), which uses the correct field names and was
  not affected — `NetworkMonitor` exists as a second, independent
  detection path for the same technique.
- T1021 (`_check_t1021` in `causal_graph.py`) is the one rule with no scope
  exclusion at all — not even the namespace-level check every other
  behavioral rule has (`_is_whitelisted`, namespace-only since the pod-name
  whitelist was removed). It fires on any `kubectl exec` into any pod,
  including routine admin access into a `kube-system` component. Whether
  that's intentional (all remote exec is inherently worth flagging,
  regardless of target) or should get the same namespace exclusion as the
  other rules is an open design question, not yet resolved.
- 120-second correlation window — an attack chain must complete inside that
  window to be linked. Configurable.

## Status

- [x] Environment: kind + Tetragon
- [x] Pod UID resolver + Tetragon consumer
- [x] Causal graph + MITRE correlation rules (11 techniques, 5 chains)
- [x] Live SOC dashboard (attack graph, alert feed, MITRE legend, sparkline)
- [x] Container escape / privilege escalation / resource abuse / RBAC abuse detection
- [x] Ablation study + benign controls + latency capture
- [x] Re-validate T1610 false-positive rate on benign traffic after burst-threshold fix
      (confirmed in a reduced live run via `week4/run_benign_controls.py` — see
      Evaluation section above for the numbers)
- [ ] Full 10-trial run of `week4/run_benign_controls.py` for the paper's final numbers
- [ ] Multi-node cluster validation
- [ ] Write-up / paper
