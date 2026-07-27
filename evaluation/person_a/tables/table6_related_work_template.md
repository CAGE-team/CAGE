# Table 6 — Related Work Comparison (template, no CSV/experiment backs this)

Fill in based on each system's published description — this is a literature
table, not something CAGE's own scripts generate. Systems named per
DEMO_GUIDE.md's "What Makes CAGE Unique" section (K8NTEXT, UNICORN, PACED)
plus Falco and vanilla Tetragon as widely-deployed baselines reviewers will
already know.

| System | Telemetry sources | Multi-hop chain detection | K8s pod-identity correlation | Live dashboard | FP mitigation approach |
|---|---|---|---|---|---|
| Falco | Syscalls (eBPF/kernel module) | No (single-event rules) | No (container ID only) | No (log/alert sink only) | Static rule tuning |
| Tetragon (standalone) | eBPF (process, network, file) | No (single-event policies) | Partial (pod labels via K8s API) | No | Static policy tuning |
| K8NTEXT | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
| UNICORN | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
| PACED | _fill in_ | _fill in_ | _fill in_ | _fill in_ | _fill in_ |
| **CAGE (this work)** | eBPF (Tetragon) + K8s audit log + pod UID cache | **Yes — 5 documented chains, 120s correlation window** | **Yes — pod UID as correlation key (immutable, unlike IP/name)** | **Yes — SSE-streamed multi-page dashboard** | Namespace-scoped exclusion (not name-based — see Ablation/Limitations) |

Notes for whoever fills this in:
- Cite the specific paper/release for K8NTEXT/UNICORN/PACED; don't rely on
  memory for their exact capabilities.
- If any of them publish their own benchmark numbers for comparable
  techniques, note them in a second small table rather than cramming into
  this one — this table should stay a clean feature comparison, not mixed
  with quantitative results that used different methodologies.
